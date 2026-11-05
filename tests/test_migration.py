import argparse
import base64
import hashlib
import html
import http.cookiejar
import json
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from f5m.analysis import analyze_device, inventory, summarize_run
from f5m.auth import AuthError, decompress_mozlz4, expiry_seconds, firefox_jar, make_cookie
from f5m.cli import requirements
from f5m.collect import collect
from f5m.output import emit, metric
from f5m.parsing import Document, aligned_outbound, config_objects, summarize_graph
from f5m.store import Run, write_json
from f5m.transport import Client, FetchError, ihealth_url


def literal_lz4(payload):
    size = len(payload)
    prefix = bytearray([min(15, size) << 4])
    if size >= 15:
        rest = size - 15
        while rest >= 255:
            prefix.append(255)
            rest -= 255
        prefix.append(rest)
    return b"mozLz40\0" + struct.pack("<I", size) + prefix + payload


def graph(rows, labels=None, units="Bits/sec", interval="600"):
    labels = labels or {"val0": "Service"}
    criteria = {"title": "Test graph", "ylabel": units}
    for key, label in labels.items():
        criteria["ll" + key[3:]] = label
        criteria["i" + key[3:]] = interval
    return {"success": True, "data": {"data": rows, "criteria": criteria}}


def page(host="edge.example.test", role="active", count=1):
    return f'''<html><title>{host} | F5 iHealth</title>
    <table><tr><td>Hostname</td><td>{host}</td></tr>
    <tr><td>Platform</td><td>Test appliance</td></tr>
    <tr><td>Version - Edition</td><td>17.x</td></tr>
    <tr><td>Generation Date</td><td>2026-01-01</td></tr></table>
    <dl><dt>Status</dt><dd>FAILOVER {role} for one day</dd>
    <dt>Virtuals</dt><dd>{count}</dd></dl>
    <table><tr><td>Local Traffic (LTM)</td><td>X</td><td>Nominal</td></tr></table></html>'''


def record_command(run, qid, name, text):
    run.record(qid, "command", name, f"https://ihealth.f5.com/qkview-analyzer/qv/{qid}/commands/view/test",
               "<html><pre>" + html.escape(text) + "</pre></html>", html=True)


def basic_run(root, qid="90000001", customer="Synthetic Alpha", hostname="alpha.example.test"):
    run = Run.create(customer, [qid], {"target_modules": ["ltm"], "growth_factor": None}, root)
    run.record(qid, "page", "overview", raw=page(hostname), html=True)
    return run


VIRTUAL = '''ltm virtual /Common/app {
    enabled
    partition Common
    profiles { /Common/http { context all } }
    policies none
    rules none
    app-service none
    fw-enforced-policy none
    fw-staged-policy none
    fw-rules none
    mirror disabled
}'''


class ParserTests(unittest.TestCase):
    def test_pre_preserves_quoted_braces_and_drops_scripts(self):
        text = 'ltm virtual /Common/app {\n description "a { quoted } value"\n profiles { /Common/http { context all } }\n}'
        doc = Document("<script>bad()</script><pre>" + html.escape(text) + "</pre>")
        self.assertNotIn("bad()", doc.text)
        self.assertEqual(doc.command, text)
        objects = config_objects(doc.command, "ltm virtual")
        self.assertEqual(objects["/Common/app"].value("description"), "a { quoted } value")

    def test_truncated_config_is_not_empty(self):
        with self.assertRaises(ValueError):
            config_objects("ltm virtual /Common/app { profiles {", "ltm virtual")
        self.assertIsNone(config_objects("No data found in QKView", "ltm virtual"))

    def test_nested_summary_headers_and_multicolumn_rows(self):
        raw = '''<table><tr><td><table><tr><td>Back</td></tr></table></td>
        <td class="header">Generation Date</td><td class="value">Yesterday</td></tr>
        <tr><td class="header">Hostname</td><td class="value">edge.test</td>
        <td class="header">Platform</td><td class="value">Platform X</td>
        <td class="header">Version - Edition</td><td class="value">Version Y</td></tr></table>'''
        result = inventory(raw)
        self.assertEqual(result["platform"], "Platform X")
        self.assertEqual(result["generation_date"], "Yesterday")
        self.assertTrue(result["parse_complete"])

    def test_statistics_missing_and_invalid_are_not_zero(self):
        data = graph([{"time": str(i), "val0": value} for i, value in enumerate([0, 10, None, -3, float("nan"), True])])
        stats = summarize_graph(data)["series"]["val0"]
        self.assertEqual(stats["valid"], 2)
        self.assertEqual(stats["missing_or_invalid"], 4)
        self.assertEqual(stats["mean"], 5)
        self.assertEqual(stats["p95"], 10)
        self.assertIsNone(stats["last"])

    def test_outbound_is_aligned_not_sum_of_independent_maxima(self):
        left = graph([{"time": "a", "val1": 100}, {"time": "b", "val1": 1}], {"val1": "Client Bits Out"})
        right = graph([{"time": "a", "val1": 1}, {"time": "b", "val1": 100}], {"val1": "Server Bits Out"})
        self.assertEqual(aligned_outbound(left, right)["max"], 101)
        right["data"]["criteria"]["i1"] = "60"
        with self.assertRaises(ValueError):
            aligned_outbound(left, right)

    def test_duplicate_graph_times_rejected(self):
        with self.assertRaises(ValueError):
            summarize_graph(graph([{"time": "a", "val0": 1}, {"time": "a", "val0": 2}]))

    def test_unfamiliar_units_not_labeled_as_bps(self):
        device = {"graphs": {"throughput": {"units": "Bytes/sec", "series": {"val0": {"label": "Service", "max": 500}}}}}
        self.assertIsNone(metric(device, "throughput", "Service"))


class FindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.qid = "90000001"
        self.run = basic_run(Path(self.temp.name) / "run")

    def cmd(self, name, content):
        record_command(self.run, self.qid, name, content)

    def setup_asm(self, action="disable", condition="none", override=False):
        virtual = VIRTUAL.replace("policies none", "policies { /Common/waf }")
        virtual = virtual.replace("/Common/http { context all }", "/Common/http { context all } /Common/websecurity { context all }")
        if override:
            virtual = virtual.replace("rules none", "rules { /Common/override }")
            self.cmd("list /ltm rule", "ltm rule /Common/override {\n when HTTP_REQUEST { ASM::enable }\n}")
        self.cmd("list /ltm virtual all-properties", virtual)
        self.cmd("list /ltm policy all-properties", f'''ltm policy /Common/waf {{
          controls {{ asm }}
          rules {{ default {{ actions {{ 1 {{ asm\n request\n {action}\n }} }}\n conditions {condition}\n }} }}
          strategy /Common/first-match
        }}''')
        self.cmd("show /ltm policy", "Ltm::Policy: /Common/waf\n | default 1 [asm disable] 42 42\n")

    def test_unconditional_asm_disable_is_bypass_not_inspection(self):
        self.setup_asm()
        result = analyze_device(self.run, self.qid)
        self.assertEqual(result["modules"]["ASM"]["state"], "configured_bypassed")
        self.assertEqual(result["modules"]["ASM"]["action_counts"]["/Common/waf"][0]["succeeded"], 42)

    def test_conditional_disable_is_not_global_bypass(self):
        self.setup_asm(condition="{ 0 { http-uri\n path\n values { /bypass } } }")
        result = analyze_device(self.run, self.qid)
        self.assertEqual(result["modules"]["ASM"]["state"], "configured_review_activity")

    def test_enable_and_irule_override_require_review(self):
        self.setup_asm(action="enable")
        self.assertEqual(analyze_device(self.run, self.qid)["modules"]["ASM"]["state"], "configured_review_activity")
        self.setup_asm(override=True)
        self.assertEqual(analyze_device(self.run, self.qid)["modules"]["ASM"]["state"], "configured_review_activity")

    def test_missing_rules_prevent_definitive_bypass(self):
        self.setup_asm()
        raw = self.run.command(self.qid, "list /ltm virtual all-properties").replace("rules none", "rules { /Common/not-captured }")
        self.cmd("list /ltm virtual all-properties", raw)
        result = analyze_device(self.run, self.qid)
        self.assertEqual(result["modules"]["ASM"]["state"], "configured_review_activity")

    def test_missing_modules_not_assumed_unused(self):
        result = analyze_device(self.run, self.qid)
        self.assertEqual(result["modules"]["ASM"]["state"], "incomplete")
        self.assertEqual(result["modules"]["APM"]["state"], "incomplete")
        self.assertEqual(result["modules"]["AFM"]["state"], "incomplete")

    def test_apm_history_vs_current(self):
        self.cmd("list /ltm virtual all-properties", VIRTUAL)
        self.cmd("show /apm profile access all", "ACCESS Profile: access\ntotal sessions: 5\ncurrent active sessions: 0")
        self.assertEqual(analyze_device(self.run, self.qid)["modules"]["APM"]["state"], "historical_activity")

    def test_dos_history_not_firewall_rule_usage(self):
        self.cmd("list /ltm virtual all-properties", VIRTUAL)
        self.cmd("list /net route-domain all-properties", "net route-domain /Common/0 {\n fw-rules none\n fw-enforced-policy none\n }")
        self.cmd("show /security firewall", "Aggregate number of micro-rules 0")
        self.cmd("show /security dos device-config", "Security::DOS/stat: No Listener Match\n  Attack Count    3\n  Attack Detected 0\n  Drops      500\n  Drops Rate 0")
        result = analyze_device(self.run, self.qid)
        self.assertEqual(result["modules"]["AFM"]["state"], "no_firewall_rules_observed")
        self.assertIn("DEVICE_DOS_ACTIVITY", {f["code"] for f in result["findings"]})

    def test_tls_inconsistency_is_flagged_not_removed(self):
        self.run.record(self.qid, "graph", "SSLTPSGraph", raw=json.dumps(graph([{"time": "a", "val0": 5000}], {"val0": "SSL TPS"}, "SSL Trans/sec")))
        self.run.record(self.qid, "graph", "newcons", raw=json.dumps(graph([{"time": "a", "val0": 5}], {"val0": "Client Connections"}, "New Conns/sec")))
        result = analyze_device(self.run, self.qid)
        self.assertIn("TLS_COUNTER_INCONSISTENCY", {f["code"] for f in result["findings"]})
        self.assertEqual(result["graphs"]["SSLTPSGraph"]["series"]["val0"]["max"], 5000)


class IsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_new_customer_has_no_prior_inputs_or_evidence(self):
        alpha = basic_run(self.root / "alpha", "90000001", "Customer Alpaca", "alpaca.example.test")
        beta = basic_run(self.root / "beta", "90000002", "Customer Badger", "badger.example.test")
        alpha.record("90000001", "graph", "throughput", raw=json.dumps(graph([{"time": "a", "val0": 12345678}])))
        result = summarize_run(beta)
        serialized = json.dumps(result)
        for forbidden in ("Alpaca", "alpaca.example.test", "90000001", "12345678"):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(result["devices"][0]["graphs"], {})
        with self.assertRaises(ValueError):
            beta.record("90000001", "page", "overview", raw="unrelated")

    def test_nonempty_output_and_changed_hash_rejected(self):
        run = basic_run(self.root / "run")
        with self.assertRaises(ValueError):
            Run.create("Another", ["90000002"], {}, run.root)
        item = run.item("90000001", "page", "overview")
        run.path(item["path"]).write_text("modified")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            Run.load(run.root)

    def test_path_escape_rejected(self):
        run = basic_run(self.root / "run")
        with self.assertRaises(ValueError):
            run.path("../../other-customer/secrets")

    def test_unknown_target_and_no_default_growth(self):
        values = requirements(argparse.Namespace())
        self.assertIsNone(values["target_modules"])
        self.assertIsNone(values["growth_factor"])
        with self.assertRaises(ValueError):
            requirements(argparse.Namespace(growth_factor=float("nan")))
        self.assertEqual(requirements(argparse.Namespace(), {"target_modules": ["ltm"]})["deployment"], "compare")

    def test_report_is_not_overwritten_by_reanalysis(self):
        run = basic_run(self.root / "run")
        emit(run, summarize_run(run))
        report = run.root / "report.md"
        report.write_text("User-authored report")
        emit(run, summarize_run(run))
        self.assertEqual(report.read_text(), "User-authored report")
        self.assertTrue((run.root / "evidence-summary.md").exists())

    def test_ha_groups_require_members_not_similar_names(self):
        run = Run.create("Topology", ["90000001", "90000002"], {}, self.root / "run")
        for qid, host, role in [("90000001", "east.example.test", "active"), ("90000002", "west.example.test", "standby")]:
            run.record(qid, "page", "overview", raw=page(host, role), html=True)
            record_command(run, qid, "list /cm device-group", "cm device-group /Common/pair {\n type sync-failover\n devices { /Common/east.example.test { } /Common/west.example.test { } }\n }")
        result = summarize_run(run)
        self.assertEqual(len(result["ha_groups"]), 1)
        self.assertEqual(result["ha_groups"][0]["active_qids"], ["90000001"])
        self.assertEqual(result["ha_groups"][0]["missing_members"], [])


class AuthTests(unittest.TestCase):
    def test_lz4_literals_overlap_and_malformed_inputs(self):
        payload = b'{"cookies": []}'
        self.assertEqual(decompress_mozlz4(literal_lz4(payload)), payload)
        overlap = b"mozLz40\0" + struct.pack("<I", 9) + b"\x32abc\x03\x00"
        self.assertEqual(decompress_mozlz4(overlap), b"abcabcabc")
        for invalid in (b"bad", overlap[:-1], b"mozLz40\0" + struct.pack("<I", 9) + b"\x00\x00\x00"):
            with self.assertRaises(ValueError):
                decompress_mozlz4(invalid)

    def test_firefox_both_cookie_stores_and_container_isolation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db = sqlite3.connect(root / "cookies.sqlite")
            db.execute("CREATE TABLE moz_cookies(host,path,isSecure,expiry,name,value,originAttributes)")
            db.executemany("INSERT INTO moz_cookies VALUES(?,?,?,?,?,?,?)", [
                ("ihealth.f5.com", "/qkview-analyzer", 1, 2000000000000, "JSESSIONID", "synthetic-main", ""),
                ("ihealth.f5.com", "/qkview-analyzer", 1, 2000000000000, "JSESSIONID", "synthetic-container", "^userContextId=2"),
                ("elsewhere.test", "/", 1, 2000000000, "private", "do-not-import", "")])
            db.commit()
            db.close()
            backups = root / "sessionstore-backups"
            backups.mkdir()
            cookies = {"cookies": [{"host": "ihealth.f5.com", "name": "BIGipServeriHealth2", "value": "synthetic-affinity", "secure": True, "originAttributes": {"userContextId": 0}}]}
            (backups / "recovery.jsonlz4").write_bytes(literal_lz4(json.dumps(cookies).encode()))
            values = {c.name: c.value for c in firefox_jar(root)}
            self.assertEqual(values, {"JSESSIONID": "synthetic-main", "BIGipServeriHealth2": "synthetic-affinity"})
            self.assertEqual({c.value for c in firefox_jar(root, 2)}, {"synthetic-container"})
            self.assertEqual(expiry_seconds(2000000000000), 2000000000)

    def test_origin_restriction(self):
        for url in ("https://elsewhere.test/qkview-analyzer/", "http://ihealth.f5.com/qkview-analyzer/", "https://user:pass@ihealth.f5.com/qkview-analyzer/", "/qkview-analyzer/logoff"):
            with self.assertRaises(ValueError):
                ihealth_url(url)

    def test_auth_redirect_retries_without_following_or_mutating_cookie(self):
        class Response:
            url = "https://ihealth.f5.com/qkview-analyzer/"
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return b"F5 iHealth"
        class Opener:
            def __init__(self): self.requests = []
            def open(self, request, timeout):
                self.requests.append(request)
                if len(self.requests) == 1:
                    raise urllib.error.HTTPError(request.full_url, 302, "redirect", {"Location": "https://login.example.test"}, None)
                return Response()
        jar = http.cookiejar.CookieJar()
        jar.set_cookie(make_cookie("ihealth.f5.com", "/", True, None, "JSESSIONID", "synthetic"))
        opener = Opener()
        self.assertEqual(Client(jar, opener, sleep=lambda _: None).get("/qkview-analyzer/"), "F5 iHealth")
        self.assertEqual(len(opener.requests), 2)
        self.assertTrue(all(r.full_url.startswith("https://ihealth.f5.com/") for r in opener.requests))

    def test_search_paginates_all_new_results(self):
        class SearchClient(Client):
            def get(self, path):
                start = int(urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)["start"][0])
                return json.dumps({"recordsFiltered": 3, "data": [["90000001"], ["90000002"]] if start == 0 else [["90000003"]]})
        client = SearchClient(http.cookiejar.CookieJar())
        self.assertEqual(client.search("https://ihealth.f5.com/qkview-analyzer/?query=new-customer&showAll=true"), ["90000001", "90000002", "90000003"])


class CollectionTests(unittest.TestCase):
    def test_collection_resume_and_failed_evidence_are_run_scoped(self):
        class FakeClient:
            def __init__(self): self.calls = []
            def get(self, url):
                self.calls.append(url)
                if "/status/overview" in url:
                    return page("new-customer.example.test")
                if "/commands/map/" in url:
                    return json.dumps({"commands": {"children": [{"data": {"title": "list /ltm virtual all-properties", "attr": {"href": "/qkview-analyzer/qv/90000009/commands/view/freshlink"}}}]}})
                if "/commands/view/freshlink" in url:
                    return "<pre>" + html.escape(VIRTUAL) + "</pre>"
                if "/graphs/i/" in url:
                    return json.dumps(graph([{"time": "2026-01-01 00:00:00", "val0": 5}]))
                if "/diagnostics/" in url:
                    return "Category,Title\n"
                return "<html><title>F5 iHealth</title></html>"
        with tempfile.TemporaryDirectory() as temp:
            run = Run.create("Fresh customer", ["90000009"], {}, Path(temp) / "run")
            client = FakeClient()
            collect(client, run)
            self.assertEqual(run.manifest["collection_state"], "collected")
            self.assertTrue(all("/90000009/" in url for url in client.calls))
            self.assertTrue(any("freshlink" in url for url in client.calls))
            self.assertEqual(len(analyze_device(run, "90000009")["virtuals"]), 1)
            prior = len(client.calls)
            collect(client, Run.load(run.root))
            self.assertEqual(len(client.calls), prior)

    def test_interrupted_authentication_retains_partial_run(self):
        class ExpiredClient:
            def get(self, url): raise AuthError("Expired")
        with tempfile.TemporaryDirectory() as temp:
            run = Run.create("Fresh customer", ["90000010", "90000011"], {}, Path(temp) / "run")
            with self.assertRaises(AuthError):
                collect(ExpiredClient(), run)
            self.assertEqual(Run.load(run.root).manifest["collection_state"], "partial")
            self.assertEqual(len(run.manifest["artifacts"]), 1)
            self.assertEqual(run.item("90000010", "page", "overview")["status"], "auth_required")


if __name__ == "__main__":
    unittest.main()
