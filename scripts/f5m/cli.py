import argparse
from datetime import date
import json
import math
from pathlib import Path
import sys

from . import VERSION
from .analysis import summarize_run
from .auth import AuthError
from .collect import collect
from .output import SKILL_ROOT, emit
from .store import Run, now, validate_ids, write_json
from .transport import Client, FetchError


def requirement_args(parser):
    parser.add_argument("--target-modules", help="Comma-separated target modules, e.g. ltm or ltm,asm. Omitted means unknown, not LTM-only.")
    parser.add_argument("--deployment", choices=("compare", "appliance", "ve"))
    parser.add_argument("--growth-factor", type=float, help="Explicit planning multiplier; no automatic growth assumption")
    parser.add_argument("--deadline", help="YYYY-MM-DD migration deadline")
    parser.add_argument("--notes", help="Additional customer-specific constraints")


def auth_args(parser):
    parser.add_argument("--firefox-profile", help="Firefox profile directory; otherwise discover the active/default profile")
    parser.add_argument("--firefox-container", type=int, default=0, help="Firefox container ID, default 0")


def requirements(args, previous=None):
    result = {"target_modules": None, "deployment": "compare", "growth_factor": None,
              "deadline": None, "virtualization": None, "site_constraints": None, "notes": None}
    result.update(previous or {})
    if getattr(args, "requirements", None):
        value = json.loads(Path(args.requirements).expanduser().read_text())
        if not isinstance(value, dict):
            raise ValueError("Requirements file must be a JSON object")
        result.update(value)
    for key in ("target_modules", "deployment", "growth_factor", "deadline", "notes"):
        value = getattr(args, key, None)
        if value is not None:
            result[key] = value
    modules = result.get("target_modules")
    if isinstance(modules, str):
        modules = [m.strip().lower() for m in modules.split(",") if m.strip()]
    if modules is not None:
        if not isinstance(modules, list) or not modules or any(not isinstance(m, str) for m in modules):
            raise ValueError("target_modules must be a nonempty list/string, or null when unknown")
        aliases = {"gtm": "dns", "iruleslx": "ilx", "awaf": "asm", "waf": "asm"}
        result["target_modules"] = sorted({aliases.get(m.lower(), m.lower()) for m in modules})
    factor = result.get("growth_factor")
    if factor is not None and (isinstance(factor, bool) or not isinstance(factor, (int, float)) or not math.isfinite(factor) or factor < 1):
        raise ValueError("growth_factor must be a finite number >=1")
    if result.get("deployment") not in ("compare", "appliance", "ve"):
        raise ValueError("deployment must be compare, appliance, or ve")
    if result.get("deadline"):
        date.fromisoformat(result["deadline"])
    return result


def parser():
    root = argparse.ArgumentParser(description="Collect new iHealth QKViews and generate a compact migration evidence brief.")
    root.add_argument("--version", action="version", version=VERSION)
    sub = root.add_subparsers(dest="action", required=True)
    analyze = sub.add_parser("analyze", help="Start an isolated analysis of NEW QKViews")
    analyze.add_argument("--customer", required=True)
    source = analyze.add_mutually_exclusive_group(required=True)
    source.add_argument("--qkviews", nargs="+", help="QKView IDs separated by spaces or commas")
    source.add_argument("--search-url", help="iHealth search URL with a non-empty query; all matching pages are retrieved")
    analyze.add_argument("--requirements", help="JSON intake file; explicit command-line values override it")
    analyze.add_argument("--output", help="New/empty run directory; default ~/Documents/F5-Migrations/<customer>/<unique-run>")
    analyze.add_argument("--days", type=int, choices=(1, 7, 30), default=30)
    requirement_args(analyze)
    auth_args(analyze)
    resume = sub.add_parser("resume", help="Retry missing/failed evidence for this exact run and ID set")
    resume.add_argument("--run", required=True)
    auth_args(resume)
    summarize = sub.add_parser("summarize", help="Re-analyze THIS run offline; optionally update target requirements")
    summarize.add_argument("--run", required=True)
    requirement_args(summarize)
    inspect = sub.add_parser("inspect", help="Print one compact section from an existing run")
    inspect.add_argument("--run", required=True)
    inspect.add_argument("--qid", required=True)
    inspect.add_argument("--section", choices=("inventory", "licensing", "hotfix_changes", "trunks", "trunk_rates", "modules", "graphs", "findings", "virtuals", "collection_gaps", "ha_groups"), required=True)
    inspect.add_argument("--name", help="Module/graph key, finding code, or exact virtual-server name")
    doctor = sub.add_parser("doctor", help="Verify Firefox session reuse without creating a customer run")
    auth_args(doctor)
    sub.add_parser("catalog", help="Print the dated platform reference catalog")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    run = None
    try:
        if args.action == "catalog":
            print((SKILL_ROOT / "references/platforms.json").read_text())
            return 0
        if args.action == "doctor":
            Client.from_firefox(args.firefox_profile, args.firefox_container)
            print("Firefox iHealth session verified. Credentials stayed in memory; no customer evidence collected.")
            return 0
        if args.action == "analyze":
            intake = requirements(args)
            ids = validate_ids(args.qkviews) if args.qkviews else None
            client = Client.from_firefox(args.firefox_profile, args.firefox_container)
            if ids is None:
                ids = client.search(args.search_url)
                if not ids:
                    raise ValueError("The search returned no QKViews")
            run = Run.create(args.customer, ids, intake, args.output,
                             {"type": "search", "url": args.search_url} if args.search_url else None,
                             {"days": args.days})
            print(f"Run: {run.root}", flush=True)
            collect(client, run)
        else:
            run = Run.load(args.run)
            if args.action == "resume":
                collect(Client.from_firefox(args.firefox_profile, args.firefox_container), run)
            elif args.action == "summarize":
                old = json.loads((run.root / "intake.json").read_text())
                new = requirements(args, old)
                if old != new:
                    history_path = run.root / "intake-history.json"
                    history = json.loads(history_path.read_text()) if history_path.exists() else []
                    history.append({"replaced_at": now(), "requirements": old})
                    write_json(history_path, history)
                    write_json(run.root / "intake.json", new)
            elif args.action == "inspect":
                if args.qid not in run.manifest["qkview_ids"]:
                    raise ValueError("QKView ID is outside this run")
                path = run.root / "analysis" / args.qid / "device-summary.json"
                if not path.exists():
                    raise ValueError("Run summarize first")
                value = json.loads(path.read_text())[args.section]
                if args.section == "virtuals" and not args.name:
                    raise ValueError("Use --name with an exact virtual-server name to avoid dumping the entire configuration")
                if args.name:
                    if isinstance(value, dict):
                        if args.name not in value:
                            raise ValueError("Requested name is absent from this section")
                        value = value[args.name]
                    else:
                        value = [v for v in value if v.get("name") == args.name or v.get("code") == args.name]
                print(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False))
                return 0
        summary = summarize_run(run)
        path = emit(run, summary)
        print(f"Brief: {path}\nDetails: {run.root / 'findings.json'}\nReport outline: {run.root / 'report-outline.md'}")
        return 2 if run.manifest["collection_state"] == "partial" else 0
    except (AuthError, FetchError, ValueError, OSError, KeyError, TypeError) as exc:
        if run and args.action in ("analyze", "resume"):
            run.manifest["collection_state"] = "partial"
            run.save()
            try:
                emit(run, summarize_run(run))
            except (ValueError, OSError, KeyError, TypeError):
                pass
            print(f"Partial run retained: {run.root}. Resume after resolving the issue.", file=sys.stderr)
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
