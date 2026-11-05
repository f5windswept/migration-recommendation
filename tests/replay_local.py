"""Development-only replay adapter for explicitly selected original collector artifacts.

No default directory or QKView IDs. No network, Firefox access, or customer fixtures
are bundled. Each replay creates a new isolated run for verification.
"""
import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from f5m.analysis import summarize_run
from f5m.collect import COMMANDS, GRAPHS
from f5m.output import emit
from f5m.parsing import command_map
from f5m.store import Run, validate_ids


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-dir", required=True)
    parser.add_argument("--qkviews", nargs="+", required=True)
    parser.add_argument("--customer", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    ids = validate_ids(args.qkviews)
    source = Path(args.legacy_dir).expanduser().resolve()
    run = Run.create(args.customer, ids, {"target_modules": None, "growth_factor": None}, args.output,
                     {"type": "explicit_development_replay"})
    for qid in ids:
        map_path = source / f"qkview-analyzer_qv_{qid}_commands_map.txt"
        mapping = command_map(json.loads(map_path.read_text())) if map_path.exists() else {}
        for name in ("overview", "ha", "licensing"):
            path = source / f"qkview-analyzer_qv_{qid}_status_{name}.raw"
            if path.exists():
                run.record(qid, "page", name, f"https://ihealth.f5.com/qkview-analyzer/qv/{qid}/status/{name}", path.read_text(), html=True)
        for name in COMMANDS:
            old_name = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
            path = source / f"{qid}-cmd-{old_name}.html"
            if path.exists():
                run.record(qid, "command", name, "https://ihealth.f5.com" + mapping[name] if name in mapping else None, path.read_text(), html=True)
            else:
                run.record(qid, "command", name, status="unavailable", error="Not present in explicitly selected replay artifacts")
        for name in GRAPHS:
            path = source / f"{qid}-graph-{name}.json"
            if path.exists():
                run.record(qid, "graph", name, raw=path.read_text())
        path = source / f"qkview-analyzer_qv_{qid}_diagnostics_download_type_csv.raw"
        if path.exists():
            run.record(qid, "csv", "diagnostics", raw=path.read_text())
    run.manifest["collection_state"] = "offline_replay"
    run.save()
    print(emit(run, summarize_run(run)))


if __name__ == "__main__":
    main()
