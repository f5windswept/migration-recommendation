"""Deterministic evidence analysis. Findings are observations, never purchase approvals."""
import csv
import io
import json
import re

from .collect import GRAPHS
from .parsing import (Document, aligned_outbound, config_objects, graph_data,
                      has_capture, irules, numeric, summarize_graph)


MODULE_NAMES = {"AFM": "AFM", "APM": "APM", "ASM": "ASM", "AVR": "AVR",
                "DNS": "DNS", "GTM": "DNS", "iRulesLX": "ILX", "LTM": "LTM",
                "PEM": "PEM", "CGNAT": "CGNAT", "SSLO": "SSLO", "vCMP": "vCMP"}


def table_pairs(document):
    return {row[0]: row[1] for table in document.tables for row in table if len(row) == 2}


def inventory(raw):
    if not raw:
        return {"hostname": None, "role": "unknown", "provisioned_modules": [], "parse_complete": False}
    doc = Document(raw)
    pairs = dict(doc.definitions)
    pairs.update(table_pairs(doc))
    pairs.update(doc.header_fields)
    counts = {}
    for name in ("Virtuals", "Pools", "Nodes", "iRules", "SNATs", "NATs", "Access Profiles"):
        value = pairs.get(name)
        if value and value.replace(",", "").isdigit():
            counts[name] = int(value.replace(",", ""))
    role = re.search(r"\bFAILOVER\s+(active|standby|offline|forced-offline)\b", doc.text, re.I)
    modules, lifecycle = [], []
    for table in doc.tables:
        for row in table:
            if len(row) >= 3 and row[2].lower() in ("nominal", "minimum", "dedicated"):
                label = re.search(r"\(([^)]+)\)", row[0])
                if label:
                    modules.append(MODULE_NAMES.get(label[1], label[1]))
            if len(row) >= 2 and re.match(r"\w{3} \d{2} \d{4}$", row[0]) and "End of" in row[1]:
                lifecycle.append({"date": row[0], "milestone": row[1]})
    bundle = re.search(r"Licensing and Provisioning \(([^)]+)\)", doc.text)
    build = re.search(r"\bbuild:\s*([^,)]+)", doc.text)
    return {"hostname": pairs.get("Hostname"), "platform": pairs.get("Platform"),
            "version": pairs.get("Version - Edition"), "build": build[1].strip() if build else None, "generation_date": pairs.get("Generation Date"),
            "role": role[1].lower() if role else "unknown", "physical_memory": pairs.get("Physical Memory"),
            "cpu_description": pairs.get("CPU Totals"), "uptime": pairs.get("Uptime"), "counts": counts,
            "bundle": bundle[1] if bundle else None, "provisioned_modules": sorted(set(modules)),
            "lifecycle": lifecycle, "parse_complete": bool(pairs.get("Hostname") and pairs.get("Platform"))}


def ha_from_page(raw):
    if not raw:
        return []
    groups, current = [], None
    for table in Document(raw).tables:
        pairs = {row[0]: row[1] for row in table if len(row) == 2}
        if pairs.get("Type") in ("sync-only", "sync-failover"):
            current = {"name": pairs.get("Name"), "type": pairs["Type"], "members": []}
            groups.append(current)
        elif current and pairs.get("Name") and "Member State" in pairs:
            current["members"].append(pairs["Name"].rsplit("/", 1)[-1])
    return groups


def get_names(node, key):
    value = node.child(key)
    if not value or value.head[1:] == ("none",):
        return []
    if value.children is not None:
        return [child.head[0] for child in value.children if child.head]
    return list(value.head[1:])


def firewall_bindings(objects):
    return [{"object": name, "field": key, "value": node.value(key) or "inline rules"}
            for name, node in (objects or {}).items()
            for key in ("fw-enforced-policy", "fw-staged-policy", "fw-rules")
            if node.child(key) and node.value(key) != "none"]


def counter_values(text, pattern):
    return [int(x.replace(",", "")) for x in re.findall(pattern, text or "", re.M)]


def policy_action_counts(text):
    result = {}
    for section in re.split(r"(?m)^Ltm::Policy:\s*", text or "")[1:]:
        name = section.splitlines()[0].strip()
        actions = []
        for action, invoked, succeeded in re.findall(r"\[asm\s+(enable|disable)\]\s+([\d,]+)\s+([\d,]+)", section):
            actions.append({"action": action, "invoked": int(invoked.replace(",", "")),
                            "succeeded": int(succeeded.replace(",", ""))})
        if actions:
            result[name] = actions
    return result


def dos_activity(text):
    result = []
    for block in re.split(r"(?m)^Security::DOS/stat:\s*", text or "")[1:]:
        fields = {key: int(value.replace(",", "")) for key, value in re.findall(
            r"(?m)^[ \t]*(Attack Detected|Attack Count|Drops|Drops Rate|Int Drops|Int Drops Rate)[ \t]+([\d,]+)[ \t]*$", block)}
        if any(fields.values()):
            result.append({"vector": block.splitlines()[0].strip(), **fields})
    return result


def analyze_device(run, qid):
    findings = []
    commands = {}

    def text(name):
        if name not in commands:
            commands[name] = run.command(qid, name)
        return commands[name]

    def evidence(*names):
        return [run.evidence(qid, "command", name) for name in names]

    def finding(code, message, refs, severity="review", details=None):
        item = {"qid": qid, "code": code, "severity": severity, "message": message, "evidence": refs}
        if details is not None:
            item["details"] = details
        findings.append(item)

    def objects(command, prefix):
        try:
            result = config_objects(text(command), prefix)
            # An HTML error or unfamiliar layout is not an empty configuration.
            if result == {} and not re.search(r"(?m)^" + re.escape(prefix) + r"\b", text(command) or ""):
                return None
            return result
        except ValueError:
            finding("CONFIG_PARSE_GAP", f"Could not parse {command}; inspect the captured text.", evidence(command))
            return None

    inv = inventory(run.raw(qid, "page", "overview"))
    inv["evidence"] = run.evidence(qid, "page", "overview")
    license_raw = run.raw(qid, "page", "licensing")
    licensing = {}
    if license_raw:
        license_doc = Document(license_raw)
        values = dict(license_doc.definitions)
        values.update(table_pairs(license_doc))
        values.update(license_doc.header_fields)
        licensing = {key: values[key] for key in ("Usage", "Licensed Version", "Service Check Date", "Perf SSL Mbps", "Perf SSL Total TPS", "Perf HTTP Compression Mbps", "CPU Throttling", "Good Better Best Licensing") if key in values}
    if not inv["parse_complete"]:
        finding("INVENTORY_GAP", "Inventory layout could not be fully parsed.", [run.evidence(qid, "page", "overview")])
    groups = ha_from_page(run.raw(qid, "page", "ha"))
    cm = objects("list /cm device-group", "cm device-group")
    if cm:
        groups = [{"name": name, "type": node.value("type"),
                   "members": [value.rsplit("/", 1)[-1] for value in get_names(node, "devices")]}
                  for name, node in cm.items()]
    virtuals = objects("list /ltm virtual all-properties", "ltm virtual")
    policies = objects("list /ltm policy all-properties", "ltm policy")
    routes = objects("list /net route-domain all-properties", "net route-domain")
    rules = irules(text("list /ltm rule"))
    bindings = []
    attached_rules = {}
    for name, node in (virtuals or {}).items():
        bound = {"name": name, "enabled": node.child("disabled") is None,
                 "partition": node.value("partition"), "profiles": get_names(node, "profiles"),
                 "policies": get_names(node, "policies"), "rules": get_names(node, "rules"),
                 "app_service": node.value("app-service"), "mirroring": node.value("mirror"),
                 "destination": node.value("destination")}
        bindings.append(bound)
        for rule in bound["rules"]:
            attached_rules.setdefault(rule, []).append(name)
    module_calls, missing_rules = [], []
    for rule, names in attached_rules.items():
        if rules is None or rule not in rules:
            missing_rules.append(rule)
            continue
        body = re.sub(r"(?m)^\s*#.*$", "", rules[rule])
        calls = sorted(set(re.findall(r"\b(?:ASM|ACCESS|ILX|DNS|AVR|BOTDEFENSE|DOSL7|ANTIFRAUD)::\w+", body)))
        if calls:
            module_calls.append({"rule": rule, "virtuals": names, "calls": calls})
    if module_calls or missing_rules:
        finding("IRULE_DEPENDENCIES", "Attached iRules have non-LTM references or unavailable bodies; trace these before removing modules.",
                evidence("list /ltm rule", "list /ltm virtual all-properties"), details={"calls": module_calls, "unavailable": missing_rules})

    # Only a single unconditional all-disable rule proves static policy bypass.
    asm_policies = {}
    for name, node in (policies or {}).items():
        if "asm" not in node.words("controls"):
            continue
        policy_rules = node.child("rules")
        decisions = []
        unconditional = bool(policy_rules and len(policy_rules.children or []) == 1)
        for rule in policy_rules.children if policy_rules else []:
            unconditional = unconditional and rule.value("conditions") == "none"
            actions = rule.child("actions")
            for action in actions.children if actions else []:
                if action.child("asm"):
                    decisions.append("disable" if action.child("disable") else "enable" if action.child("enable") else "unknown")
        asm_policies[name] = {"decisions": decisions, "unconditional_disable": unconditional and bool(decisions) and set(decisions) == {"disable"}}
    asm_vs = []
    asm_override = any("ASM::enable" in entry["calls"] or "ASM::policy" in entry["calls"] for entry in module_calls)
    for bound in bindings:
        controlling = [name for name in bound["policies"] if name in asm_policies]
        profile_hint = any(name.rsplit("/", 1)[-1] == "websecurity" or name.rsplit("/", 1)[-1].startswith("ASM_") for name in bound["profiles"])
        if controlling or profile_hint:
            bypass = bool(controlling) and all(asm_policies[name]["unconditional_disable"] for name in controlling)
            asm_vs.append({"virtual": bound["name"], "policies": controlling,
                           "static_bypass": bypass, "override_review": asm_override or bool(missing_rules)})
    action_counts = policy_action_counts(text("show /ltm policy"))
    if virtuals is None or policies is None:
        asm_state = "incomplete"
    elif asm_vs and all(item["static_bypass"] and not item["override_review"] for item in asm_vs):
        asm_state = "configured_bypassed"
        finding("ASM_BYPASS", f"{len(asm_vs)} virtual servers reference unconditional ASM-disable policies; profile attachments do not establish inspection.",
                evidence("list /ltm virtual all-properties", "list /ltm policy all-properties", "show /ltm policy", "list /ltm rule"),
                "info", {"virtuals": asm_vs, "cumulative_action_counts": action_counts})
    elif asm_vs or asm_override:
        asm_state = "configured_review_activity"
        finding("ASM_DEPENDENCY", "ASM policy/profile dependencies or dynamic overrides exist. Verify inspection/enforcement and traffic on each path.",
                evidence("list /ltm virtual all-properties", "list /ltm policy all-properties", "show /ltm policy", "list /ltm rule"), details=asm_vs)
    else:
        asm_state = "no_application_use_observed"

    apm_text = text("show /apm profile access all")
    apm_profiles = re.findall(r"ACCESS Profile:\s*(\S+)", apm_text or "")
    apm_total = counter_values(apm_text, r"^\s*total sessions:\s*([\d,]+)")
    apm_current = counter_values(apm_text, r"^\s*current active sessions:\s*([\d,]+)")
    apm_bound = [b["name"] for b in bindings if any(p.rsplit("/", 1)[-1] in {a.rsplit("/", 1)[-1] for a in apm_profiles} for p in b["profiles"])]
    apm_calls = any(any(call.startswith("ACCESS::") for call in item["calls"]) for item in module_calls)
    apm_state = ("observed_activity" if any(apm_current) else "historical_activity" if any(apm_total)
                 else "configured" if apm_bound or apm_calls else "no_application_use_observed"
                 if apm_total and virtuals is not None else "incomplete")

    dns_defs = objects("list /ltm profile dns all-properties", "ltm profile dns")
    dns_bound = [b["name"] for b in bindings if any(p in (dns_defs or {}) for p in b["profiles"])]
    dns_queries = counter_values(text("show /ltm profile dns"), r"^\s*Total Queries\s+([\d,]+)")
    gtm_queries = counter_values(text("show /gtm traffic"), r"^\s*(?:A|AAAA|CNAME|MX|NAPTR|SRV) Requests\s+([\d,]+)")
    dns_calls = any(any(call.startswith("DNS::") for call in item["calls"]) for item in module_calls)
    dns_state = ("historical_activity" if any(dns_queries + gtm_queries) else "configured" if dns_bound or dns_calls
                 else "no_application_use_observed" if dns_queries and gtm_queries and dns_defs is not None and virtuals is not None else "incomplete")

    analytics_defs = objects("list /ltm profile analytics all-properties", "ltm profile analytics")
    analytics_bound = [b["name"] for b in bindings if any(p in (analytics_defs or {}) for p in b["profiles"])]
    avr_state = "configured" if analytics_bound else "no_profile_based_use_observed" if analytics_defs is not None and virtuals is not None else "incomplete"
    plugins = objects("list ilx plugin all-properties", "ilx plugin")
    workspaces = objects("list ilx workspace all-properties", "ilx workspace")
    ilx_defs = objects("list ltm profile ilx all-properties", "ltm profile ilx")
    ilx_bound = [b["name"] for b in bindings if any(p in (ilx_defs or {}) for p in b["profiles"])]
    ilx_calls = any(any(call.startswith("ILX::") for call in item["calls"]) for item in module_calls)
    ilx_state = ("configured" if plugins or workspaces or ilx_bound or ilx_calls else "no_application_use_observed"
                 if ilx_defs is not None and virtuals is not None and rules is not None else "incomplete")

    micro_rules = counter_values(text("show /security firewall"), r"^\s*Aggregate number of micro-rules\s+([\d,]+)")
    fw_bound = firewall_bindings(virtuals) + firewall_bindings(routes)
    dos = dos_activity(text("show /security dos device-config"))
    afm_state = ("configured_firewall" if fw_bound or any(micro_rules) else "no_firewall_rules_observed"
                 if micro_rules and virtuals is not None and routes is not None else "incomplete")
    if dos:
        finding("DEVICE_DOS_ACTIVITY", "Device-level packet-validation/DoS counters contain activity. Cumulative drops/events do not prove current attacks or an AFM license requirement.",
                evidence("show /security dos device-config", "list /security dos device-config all-properties"), details=dos)
    if fw_bound or any(micro_rules):
        finding("FIREWALL_DEPENDENCY", "Configured firewall rules/policies need a target-feature decision.",
                evidence("show /security firewall", "list /net route-domain all-properties", "list /ltm virtual all-properties"), details=fw_bound)

    modules = {
        "ASM": {"state": asm_state, "virtuals": asm_vs, "policies": asm_policies, "action_counts": action_counts},
        "APM": {"state": apm_state, "profiles": apm_profiles, "total_sessions": apm_total, "current_sessions": apm_current, "attached_virtuals": apm_bound},
        "DNS": {"state": dns_state, "profile_queries": dns_queries, "gtm_queries": gtm_queries, "attached_virtuals": dns_bound},
        "AVR": {"state": avr_state, "attached_virtuals": analytics_bound, "limitation": "System/background reporting not measured by profile attachment checks"},
        "ILX": {"state": ilx_state, "plugins": list(plugins or {}), "workspaces": list(workspaces or {}), "attached_virtuals": ilx_bound,
                "limitation": "No data found in QKView is not proof of an empty plugin/workspace inventory"},
        "AFM": {"state": afm_state, "compiled_micro_rules": micro_rules, "bindings": fw_bound, "device_dos_activity": dos}}
    module_sources = {
        "ASM": ("list /ltm virtual all-properties", "list /ltm policy all-properties", "show /ltm policy", "list /ltm rule"),
        "APM": ("show /apm profile access all", "show /apm license", "list /ltm virtual all-properties"),
        "DNS": ("show /gtm traffic", "show /ltm profile dns", "list /ltm profile dns all-properties", "list /ltm virtual all-properties"),
        "AVR": ("list /ltm profile analytics all-properties", "list /ltm virtual all-properties"),
        "ILX": ("list ilx plugin all-properties", "list ilx workspace all-properties", "list ltm profile ilx all-properties", "list /ltm rule"),
        "AFM": ("show /security firewall", "list /net route-domain all-properties", "list /ltm virtual all-properties", "show /security dos device-config")}
    for name, sources in module_sources.items():
        modules[name]["evidence"] = evidence(*sources)

    raw_graphs, graphs = {}, {}
    for name in GRAPHS:
        raw = run.raw(qid, "graph", name)
        if not raw:
            continue
        try:
            value = json.loads(raw)
            graphs[name] = summarize_graph(value)
            graphs[name]["evidence"] = run.evidence(qid, "graph", name)
            raw_graphs[name] = value
            if not graphs[name]["samples"] or not graphs[name]["series"] or any(s["missing_or_invalid"] for s in graphs[name]["series"].values()):
                finding("GRAPH_COVERAGE", f"{name} has empty/missing/invalid samples; they were not treated as zero.", [run.evidence(qid, "graph", name)])
        except (ValueError, TypeError, KeyError):
            finding("GRAPH_PARSE_GAP", f"Could not interpret {name} graph.", [run.evidence(qid, "graph", name)])
    outbound = None
    if "detailthroughput1" in raw_graphs and "detailthroughput2" in raw_graphs:
        try:
            outbound = aligned_outbound(raw_graphs["detailthroughput1"], raw_graphs["detailthroughput2"])
        except ValueError as exc:
            finding("OUTBOUND_ALIGNMENT", str(exc), [run.evidence(qid, "graph", n) for n in ("detailthroughput1", "detailthroughput2")])
    if "SSLTPSGraph" in raw_graphs and "newcons" in raw_graphs:
        ssl_rows, sc = graph_data(raw_graphs["SSLTPSGraph"])
        connection_rows, cc = graph_data(raw_graphs["newcons"])
        # These labels/expressions are checked; an unfamiliar series is not guessed.
        if sc.get("ll0") == "SSL TPS" and cc.get("ll0") == "Client Connections" and sc.get("i0") == cc.get("i0"):
            connections = {row["time"]: row.get("val0") for row in connection_rows}
            traffic = {row["time"]: row.get("val0") for row in graph_data(raw_graphs["throughput"])[0]} if "throughput" in raw_graphs else {}
            suspicious = [{"time": row["time"], "ssl_tps": row["val0"], "new_client_cps": connections[row["time"]],
                           "service_bps": traffic.get(row["time"])}
                          for row in ssl_rows if numeric(row.get("val0")) and numeric(connections.get(row["time"]))
                          and row["val0"] >= 100 and row["val0"] > 10 * max(connections[row["time"]], 1)]
            if suspicious:
                finding("TLS_COUNTER_INCONSISTENCY", "SSL TPS exceeds new client CPS by >10× at >=100 TPS. Verify counter semantics/resets and actual TLS demand; do not discard spikes or size solely from them.",
                        [run.evidence(qid, "graph", n) for n in ("SSLTPSGraph", "newcons", "throughput")],
                        details={"intervals": len(suspicious), "largest": sorted(suspicious, key=lambda x: x["ssl_tps"], reverse=True)[:3]})
    if "Engineering Hotfix" in (inv.get("version") or ""):
        finding("EHF_DEPENDENCY", "Source uses an engineering hotfix; confirm required changes are included in the target release.", [run.evidence(qid, "page", "overview")])
    hotfix_changes = []
    for artifact in run.manifest["artifacts"].values():
        if artifact["qid"] != qid or artifact["kind"] != "command" or artifact["status"] != "ok" or "hotfix changes" not in artifact["name"].lower():
            continue
        document = Document(run.raw(qid, "command", artifact["name"]))
        ids = sorted({value for link in document.links if "bugzilla" in link.lower() or "bugtracker" in link.lower()
                      for value in re.findall(r"(?:[?&](?:bug_id|id)=|/ID)([0-9]+)", link)})
        hotfix_changes.append({"name": artifact["name"], "bug_ids": ids, "evidence": run.evidence(qid, "command", artifact["name"])})
    unhandled = set(inv.get("provisioned_modules", [])) - {"LTM", *modules}
    if unhandled:
        finding("ADDITIONAL_MODULES", "Additional provisioned modules need specialized sizing/use checks: " + ", ".join(sorted(unhandled)), [run.evidence(qid, "page", "overview")])
    iapps = sorted({b["app_service"] for b in bindings if b["app_service"] not in (None, "none")})
    if iapps:
        finding("IAPP_DEPENDENCIES", f"{len(iapps)} iApp/application-service dependencies found; preserve generated objects and validate target support.", evidence("list /ltm virtual all-properties"), details=iapps)
    if inv.get("counts", {}).get("Virtuals") is not None and virtuals is not None and inv["counts"]["Virtuals"] != len(virtuals):
        finding("OBJECT_COUNT_MISMATCH", "Overview and parsed virtual-server counts differ; configuration coverage needs investigation.", evidence("list /ltm virtual all-properties"))
    trunk_defs = objects("list /net trunk all-properties -hidden", "net trunk")
    trunk_details = [{"name": name, "interfaces": get_names(node, "interfaces"), "lacp": node.value("lacp")}
                     for name, node in (trunk_defs or {}).items()]
    trunk_rates = [{"name": name, "state": state, "bandwidth_mbps_text": rate}
                   for name, state, rate in re.findall(r"(?m)^([\w./-]+)[ \t]+(up|down)[ \t]+([\d.]+[KMG]?)[ \t]+", text("show /net trunk all-properties -hidden") or "")]
    diagnostics = []
    raw_csv = run.raw(qid, "csv", "diagnostics")
    if raw_csv:
        for row in csv.DictReader(io.StringIO(raw_csv)):
            title = row.get("Title", "")
            if re.search(r"memory|CPU|unsupported hardware|certificate|iRule|provision|hotfix|migration", title, re.I):
                diagnostics.append({"severity": row.get("Category"), "title": title, "reference": row.get("Solution Hyperlinks")})
    gaps = [run.evidence(qid, item["kind"], item["name"]) for item in run.manifest["artifacts"].values()
            if item["qid"] == qid and item["status"] != "ok"]
    return {"qid": qid, "inventory": inv, "licensing": licensing, "hotfix_changes": hotfix_changes, "ha_groups": groups, "modules": modules, "graphs": graphs,
            "combined_outbound": outbound, "virtuals": bindings, "route_domain_count": len(routes) if routes is not None else None,
            "iapps": iapps, "module_irule_calls": module_calls, "missing_attached_irules": missing_rules,
            "trunks": trunk_details, "trunk_rates": trunk_rates, "provisioning": text("show /sys provision"),
            "migration_diagnostics": diagnostics, "collection_gaps": gaps, "findings": findings}


def summarize_run(run):
    devices = [analyze_device(run, qid) for qid in run.manifest["qkview_ids"]]
    groups = {}
    host_ids = {}
    for device in devices:
        hostname = device["inventory"].get("hostname")
        if hostname:
            host_ids.setdefault(hostname, []).append(device["qid"])
        for group in device["ha_groups"]:
            if group["type"] != "sync-failover" or not group["members"]:
                continue
            signature = tuple(sorted(set(group["members"])))
            groups.setdefault(signature, {"members": list(signature), "reported_names": [], "evidence_qids": []})
            groups[signature]["reported_names"] = sorted(set(groups[signature]["reported_names"] + [group["name"]]))
            groups[signature]["evidence_qids"].append(device["qid"])
    for group in groups.values():
        group["missing_members"] = [host for host in group["members"] if host not in host_ids]
        group["qkview_ids"] = [qid for host in group["members"] for qid in host_ids.get(host, [])]
        group["active_qids"] = [d["qid"] for d in devices if d["qid"] in group["qkview_ids"] and d["inventory"]["role"] == "active"]
        group["sizing_note"] = "Use complete surviving-member/site workload; active/standby capacities are not additive. Multiple active members require traffic-group analysis."
    findings = [item for device in devices for item in device["findings"]]
    for hostname, ids in host_ids.items():
        if len(ids) > 1:
            findings.append({"code": "MULTIPLE_SNAPSHOTS", "severity": "review", "message": f"Multiple QKViews for {hostname}; select the intended generation before sizing.", "qids": ids})
    for group in groups.values():
        if group["missing_members"] or len(group["active_qids"]) != 1:
            findings.append({"code": "HA_SIZING_REVIEW", "severity": "review", "message": "HA group has missing peers or does not show exactly one active member; confirm traffic-group/site failover load.", "details": group})
    grouped = {qid for group in groups.values() for qid in group["qkview_ids"]}
    for device in devices:
        if device["qid"] not in grouped:
            findings.append({"qid": device["qid"], "code": "HA_UNCONFIRMED", "severity": "review", "message": "No verified sync-failover group with supplied members; do not infer peer relationships from names."})
    return {"schema_version": 1, "run_id": run.manifest["run_id"], "customer": run.manifest["customer"],
            "qkview_ids": run.manifest["qkview_ids"], "requirements": json.loads((run.root / "intake.json").read_text()),
            "collection_state": run.manifest["collection_state"], "devices": devices,
            "ha_groups": list(groups.values()), "findings": findings,
            "limitations": ["QKView evidence is historical, not live telemetry.",
                            "Maximum graph values are sampled/aggregated maxima; preserve interval and coverage.",
                            "No-data/missing captures are not zero utilization.",
                            "Static module checks do not execute Tcl or resolve every custom/dynamic feature.",
                            "Module provisioning consumes resources even without application traffic.",
                            "CPU architectures, memory-domain percentages, and TLS benchmark variants are not interchangeable."]}
