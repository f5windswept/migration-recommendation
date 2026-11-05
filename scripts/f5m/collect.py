"""Known iHealth retrieval workflow, with command links discovered for each new QKView."""
import base64
import json
import re
import sys

from .auth import AuthError
from .parsing import command_map, graph_data
from .transport import BASE, FetchError, ihealth_url

GRAPHS = ("throughput", "detailthroughput1", "detailthroughput2", "throughputpkts",
          "CPU", "detailplanestat", "memory", "activecons", "newcons", "SSLTPSGraph",
          "httprequests", "act_sessions", "GSLBGraph")
COMMANDS = (
    "list /cm device-group", "show /cm traffic-group", "show /cm sync-status",
    "list /ltm virtual all-properties", "list /ltm policy all-properties", "show /ltm policy",
    "list /ltm rule", "list /ltm profile analytics all-properties",
    "list /ltm profile dns all-properties", "show /ltm profile dns",
    "show /ltm profile client-ssl global", "show /ltm profile server-ssl global",
    "show /ltm profile http-compression global", "list /net route-domain all-properties",
    "show /net trunk all-properties -hidden", "show /net interface all-properties -hidden",
    "list /net trunk all-properties -hidden",
    "show /apm profile access all", "show /apm license", "show /gtm traffic",
    "show /gtm wideip detail", "show /ltm dns cache", "list ilx plugin all-properties",
    "list ilx workspace all-properties", "list ltm profile ilx all-properties",
    "show /security firewall", "show /security dos device-config",
    "list /security dos device-config all-properties", "list /security dos profile all-properties",
    "list /security nat policy all-properties", "show /security ip-intelligence profile",
    "show /sys provision", "show /sys memory", "show /sys pva-traffic global")


def normalized(command):
    return re.sub(r"(?<=\s)/(?=\w)", "", " ".join(command.split()))


def retrieve(client, run, qid, kind, name, path, json_check=None):
    previous = run.item(qid, kind, name)
    if previous and previous["status"] == "ok":
        return run.raw(qid, kind, name)
    url = ihealth_url(path)
    try:
        raw = client.get(url)
        if json_check:
            json_check(json.loads(raw))
        run.record(qid, kind, name, url, raw, html=kind in ("page", "command"))
        return raw
    except AuthError:
        run.record(qid, kind, name, url, status="auth_required", error="Refresh Firefox login and resume")
        raise
    except FetchError as exc:
        run.record(qid, kind, name, url, status="missing" if exc.status == 404 else "error", error=str(exc))
    except (ValueError, KeyError, TypeError):
        run.record(qid, kind, name, url, raw=raw, status="parse_error", error="Response schema differs from expected iHealth schema")
    return None


def collect(client, run):
    run.manifest["collection_state"] = "collecting"
    run.save()
    finished = False
    try:
        for index, qid in enumerate(run.manifest["qkview_ids"], 1):
            print(f"Collecting QKView {qid} ({index}/{len(run.manifest['qkview_ids'])})", file=sys.stderr)
            prefix = f"/qkview-analyzer/qv/{qid}"
            for page in ("overview", "ha", "licensing"):
                retrieve(client, run, qid, "page", page, prefix + "/status/" + page)
            raw = retrieve(client, run, qid, "map", "commands", prefix + "/commands/map/",
                           lambda data: data["commands"])
            mapping = command_map(json.loads(raw)) if raw else {}
            lookup = {normalized(title): path for title, path in mapping.items()}
            for title in COMMANDS:
                path = lookup.get(normalized(title))
                if not path:
                    if not run.item(qid, "command", title):
                        run.record(qid, "command", title, status="unavailable", error="Command absent from this QKView's command map")
                    continue
                if not re.fullmatch(re.escape(prefix) + r"/commands/view/[a-zA-Z0-9_-]+", path):
                    run.record(qid, "command", title, status="error", error="Command map link is outside this QKView")
                    continue
                retrieve(client, run, qid, "command", title, path)
            # EHF command names/links vary; discover them rather than carry IDs forward.
            for title, path in mapping.items():
                if "hotfix changes" in title.lower() and path.startswith(prefix + "/commands/view/"):
                    retrieve(client, run, qid, "command", title, path)
            days = run.manifest.get("options", {}).get("days", 30)
            for name in GRAPHS:
                encoded = base64.b64encode(f"{name}_{days * 86400}".encode()).decode()
                retrieve(client, run, qid, "graph", name, prefix + "/graphs/i/" + encoded, graph_data)
            retrieve(client, run, qid, "csv", "diagnostics", prefix + "/diagnostics/download?type=csv")
        finished = True
    finally:
        bad = [a for a in run.manifest["artifacts"].values() if a["status"] in ("error", "auth_required", "parse_error")]
        run.manifest["collection_state"] = "partial" if not finished or bad else "collected"
        run.save()
