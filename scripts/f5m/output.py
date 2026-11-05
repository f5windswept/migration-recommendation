"""Compact model-facing brief plus full, run-local drill-down evidence."""
import json
from pathlib import Path

from . import VERSION
from .store import now, write_json, write_text

SKILL_ROOT = Path(__file__).resolve().parents[2]


def cell(value):
    if value is None:
        return "unknown"
    return str(value).replace("|", "/").replace("\n", " ")


def amount(value):
    if value is None:
        return "unknown"
    if abs(value) >= 1e9:
        return f"{value / 1e9:.3g}G"
    if abs(value) >= 1e6:
        return f"{value / 1e6:.3g}M"
    if abs(value) >= 1e3:
        return f"{value / 1e3:.3g}k"
    return f"{value:.3g}"


def metric(device, graph, label, stat="max"):
    data = device["graphs"].get(graph, {})
    expected = {"throughput": "Bits/sec", "newcons": "New Conns/sec", "activecons": "Active Conns",
                "detailplanestat": "% Utilization", "SSLTPSGraph": "SSL Trans/sec", "memory": "Percent Used",
                "httprequests": "Requests/sec", "throughputpkts": "Pkts/sec"}
    if graph in expected and data.get("units") != expected[graph]:
        return None
    return next((series.get(stat) for series in data.get("series", {}).values() if series["label"] == label), None)


def candidate_screen(summary, catalog):
    # Deliberately does not pick a SKU or predict CPU/RAM/TLS performance.
    factor = summary["requirements"].get("growth_factor")
    ltm_only = summary["requirements"].get("target_modules") == ["ltm"]
    screens = []
    for device in summary["devices"]:
        if device["inventory"]["role"] == "standby":
            continue
        throughput = metric(device, "throughput", "Service")
        if throughput is None:
            continue
        screens.append({"qid": device["qid"], "scope": "throughput_screen_only",
                        "target_confirmed_ltm_only": ltm_only, "observed_service_bps": throughput,
                        "planning_multiplier": factor, "planning_service_bps": throughput * factor if factor else None,
                        "platforms": [{"model": p["model"], "published_l7_gbps": p["l7_gbps"],
                                       "observed_vs_l7_benchmark_percent": round(100 * throughput / (p["l7_gbps"] * 1e9), 3)}
                                      for p in catalog["platforms"]],
                        "unresolved_dimensions": ["instantaneous bursts", "CPU and memory on target", "TLS cipher mix and validated handshake rates",
                                                  "packet rate", "profiles/iRules", "ports and HA/site failover load", "required modules and feature compatibility"]})
    return screens


def brief(summary, catalog):
    lines = [f"# Migration evidence brief: {summary['customer']}", "",
             f"Run: `{summary['run_id']}` · Tool {VERSION} · Generated {now()}",
             "**Evidence scoped only to these QKViews:** " + ", ".join(summary["qkview_ids"]),
             f"Collection: {summary['collection_state']}. Source QKViews are historical snapshots, not live telemetry.", "",
             "## Target requirements", "",
             "```json", json.dumps(summary["requirements"], ensure_ascii=False), "```", "",
             "## Inventory", "",
             "| QKView | Host | Role | Platform / version | Virtuals | Provisioned |",
             "|---|---|---|---|---:|---|"]
    for device in summary["devices"]:
        inv = device["inventory"]
        lines.append("| " + " | ".join(map(cell, [device["qid"], inv.get("hostname"), inv["role"],
                     f"{inv.get('platform') or 'unknown'} / {inv.get('version') or 'unknown'}", inv.get("counts", {}).get("Virtuals"),
                     ", ".join(inv.get("provisioned_modules", [])) or "unknown"])) + " |")
    lines.extend(["", "## HA groups", ""])
    for group in summary["ha_groups"]:
        lines.append(f"- {', '.join(group['members'])}; active QKViews: {', '.join(group['active_qids']) or 'unknown'}; missing peers: {', '.join(group['missing_members']) or 'none'}.")
    if not summary["ha_groups"]:
        lines.append("- No verified group. Do not infer topology from hostnames.")
    lines.extend(["- Size surviving-member/site demand. Do not add active/standby licensed capacities.", "",
                  "## Workload (all available members; maxima are sampled averages)", "",
                  "| QKView | Service mean / p95 / max bps | Combined outbound max bps* | New client CPS max | Connections max | Data CPU p95 / max % | SSL TPS max |",
                  "|---|---|---|---:|---:|---|---:|"])
    for device in summary["devices"]:
        values = [device["qid"], " / ".join(amount(metric(device, "throughput", "Service", stat)) for stat in ("mean", "p95", "max")),
                  amount((device.get("combined_outbound") or {}).get("max")), amount(metric(device, "newcons", "Client Connections")),
                  amount(metric(device, "activecons", "Connections")), " / ".join(amount(metric(device, "detailplanestat", "Data Plane", stat)) for stat in ("p95", "max")),
                  amount(metric(device, "SSLTPSGraph", "SSL TPS"))]
        lines.append("| " + " | ".join(map(cell, values)) + " |")
    lines.extend(["", "*Combined outbound sums time-aligned client/server outbound samples; not a verified VE licensing counter. k/M/G are decimal multipliers.", ""])
    for device in summary["devices"]:
        graph = device["graphs"].get("throughput", {})
        intervals = sorted({str(s.get("interval_seconds")) for s in graph.get("series", {}).values()})
        lines.append(f"- {device['qid']}: capture {device['inventory'].get('generation_date')}; graph {graph.get('start')}–{graph.get('end')}; {graph.get('samples', 0)} samples; intervals {','.join(intervals) or 'unknown'} sec. Dates retain source labels.")
    lines.extend(["", "## Resources and connectivity", "",
                  "| QKView | Physical RAM | TMM / other memory max %* | HTTP RPS max | Service PPS max | Captured trunks |",
                  "|---|---|---|---:|---:|---|"])
    for device in summary["devices"]:
        trunk_desc = "; ".join(f"{t['name']}: {', '.join(t['interfaces'])}, LACP {t['lacp']}" for t in device["trunks"])
        if not trunk_desc:
            trunk_desc = "; ".join(f"{t['name']}: {t['bandwidth_mbps_text']} Mbps {t['state']}" for t in device["trunk_rates"]) or "unknown"
        values = [device["qid"], device["inventory"].get("physical_memory"),
                  " / ".join(amount(metric(device, "memory", label)) for label in ("TMM Memory Used", "Other Memory Used")),
                  amount(metric(device, "httprequests", "HTTP Requests")), amount(metric(device, "throughputpkts", "Service")), trunk_desc]
        lines.append("| " + " | ".join(map(cell, values)) + " |")
    lines.extend(["", "*Memory percentages use separate source denominators; do not sum them or multiply both by appliance RAM."])
    lines.extend(["", "## Non-LTM module evidence", "",
                  "| QKView | APM | DNS | ASM | AFM firewall | AVR | ILX |", "|---|---|---|---|---|---|---|"])
    for device in summary["devices"]:
        lines.append("| " + " | ".join([device["qid"]] + [device["modules"][name]["state"] for name in ("APM", "DNS", "ASM", "AFM", "AVR", "ILX")]) + " |")
    lines.extend(["", "Observed/historical activity, attachment, bypass, provisioning, and missing data are different. AVR background reporting and device-level DoS need separate interpretation.", "",
                  "## Findings to interpret", ""])
    for item in summary["findings"]:
        lines.append(f"- **{item.get('qid', 'run')} / {item['code']}**: {item['message']}")
    if not summary["findings"]:
        lines.append("- No automatic findings. This is not a guarantee of complete compatibility.")
    lines.extend(["", "## Lifecycle / collection coverage", ""])
    for device in summary["devices"]:
        lifecycle = "; ".join(f"{v['milestone']}: {v['date']}" for v in device["inventory"].get("lifecycle", []))
        lines.append(f"- {device['qid']}: {lifecycle or 'Lifecycle dates unavailable'}.")
        gaps = device["collection_gaps"]
        if gaps:
            lines.append(f"  {len(gaps)} unavailable/failed retrievals. Inspect device-summary.json collection_gaps; missing evidence is not zero utilization.")
        if device["migration_diagnostics"]:
            lines.append("  Migration diagnostics: " + "; ".join(cell(d["title"]) for d in device["migration_diagnostics"][:6]) + ".")
    lines.extend(["", "## Reference boundary", "",
                  f"Catalog {catalog['catalog_version']}; source document {catalog['source_document_date']}; last reviewed {catalog['last_reviewed']}.",
                  catalog["status"], catalog["benchmark_scope"],
                  "VE SKU/CPU limits and exact throughput accounting are not verified by this catalog. Check K14810/current quote.", "",
                  "## Targeted drill-down", "",
                  "Use `inspect --run <run> --qid <ID> --section modules|graphs|inventory|findings|virtuals --name <optional-key>`. Virtual-server inspection requires an exact name.",
                  "Each device has `analysis/<ID>/device-summary.json`; source links/text paths are in `evidence-index.json`. `findings.json` retains detailed counters and dependencies.",
                  "The model should author `report.md` from `report-outline.md`; this brief is evidence, not a final procurement recommendation.", ""])
    return "\n".join(lines)


def emit(run, summary):
    catalog = json.loads((SKILL_ROOT / "references/platforms.json").read_text())
    summary["tool_version"] = VERSION
    summary["generated_at"] = now()
    summary["reference_catalog"] = {k: catalog[k] for k in ("catalog_version", "source_document_date", "last_reviewed", "sources")}
    summary["candidate_screens"] = candidate_screen(summary, catalog)
    for device in summary["devices"]:
        write_json(run.root / "analysis" / device["qid"] / "device-summary.json", device)
    write_json(run.root / "evidence-summary.json", summary)
    write_json(run.root / "findings.json", summary["findings"])
    write_json(run.root / "evidence-index.json", list(run.manifest["artifacts"].values()))
    write_text(run.root / "evidence-summary.md", brief(summary, catalog))
    outline = run.root / "report-outline.md"
    if not outline.exists():
        template = (SKILL_ROOT / "templates/report.md").read_text()
        write_text(outline, template.replace("{{CUSTOMER}}", summary["customer"]).replace("{{RUN_ID}}", summary["run_id"]))
    return run.root / "evidence-summary.md"
