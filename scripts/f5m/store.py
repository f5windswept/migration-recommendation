"""Run-local evidence storage. No cross-run/customer caches or implicit inputs."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

from . import VERSION
from .parsing import Document


def now():
    return datetime.now(timezone.utc).isoformat()


def slug(value):
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip(".-")[:80] or "customer"


def validate_ids(values):
    result = []
    for value in values:
        for qid in re.split(r"[,\s]+", str(value).strip()):
            if not qid:
                continue
            if not re.fullmatch(r"[0-9]{1,20}", qid):
                raise ValueError("QKView IDs must contain only digits")
            if qid not in result:
                result.append(qid)
    if not result:
        raise ValueError("At least one QKView ID is required")
    return result


def write_json(path, data):
    write_text(path, json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n")


def write_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temp.open("x", encoding="utf-8") as stream:
            temp.chmod(0o600)
            stream.write(text)
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


class Run:
    def __init__(self, root, manifest):
        self.root = Path(root).expanduser().resolve()
        self.manifest = manifest

    @classmethod
    def create(cls, customer, ids, requirements, output=None, source=None, options=None):
        ids = validate_ids(ids)
        if not customer.strip():
            raise ValueError("A customer/run label is required")
        unique = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        root = Path(output).expanduser() if output else Path.home() / "Documents/F5-Migrations" / slug(customer) / unique
        if root.exists() and (not root.is_dir() or any(root.iterdir())):
            raise ValueError("Output must be new or empty. Use resume for an existing run; never mix customer evidence.")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root.chmod(0o700)
        run = cls(root, {"schema_version": 1, "tool_version": VERSION, "run_id": unique,
                         "customer": customer.strip(), "created_at": now(), "qkview_ids": ids,
                         "source": source or {"type": "explicit_ids"}, "options": options or {},
                         "collection_state": "new", "artifacts": {}})
        write_json(run.root / "intake.json", requirements)
        run.save()
        return run

    @classmethod
    def load(cls, root):
        root = Path(root).expanduser().resolve()
        manifest = json.loads((root / "run.json").read_text())
        if manifest.get("schema_version") != 1:
            raise ValueError("Unsupported run schema")
        ids = validate_ids(manifest.get("qkview_ids", []))
        if ids != manifest["qkview_ids"] or not manifest.get("customer"):
            raise ValueError("Invalid run identity")
        run = cls(root, manifest)
        for item in manifest["artifacts"].values():
            if item["qid"] not in ids:
                raise ValueError("Artifact belongs to a QKView outside this run")
            if item.get("status") == "ok":
                data = run.path(item["path"]).read_bytes()
                if hashlib.sha256(data).hexdigest() != item["sha256"]:
                    raise ValueError("Evidence hash mismatch; preserve the run and collect a new one")
        return run

    def path(self, relative):
        path = (self.root / relative).resolve()
        if not path.is_relative_to(self.root):
            raise ValueError("Evidence path escapes the run directory")
        return path

    def save(self):
        write_json(self.root / "run.json", self.manifest)

    @staticmethod
    def key(qid, kind, name):
        return f"{qid}|{kind}|{name}"

    def item(self, qid, kind, name):
        return self.manifest["artifacts"].get(self.key(qid, kind, name))

    def record(self, qid, kind, name, url=None, raw=None, status="ok", error=None, html=False):
        if qid not in self.manifest["qkview_ids"]:
            raise ValueError("QKView not in this run")
        item = {"qid": qid, "kind": kind, "name": name, "source_url": url,
                "collected_at": now(), "status": status}
        if raw is not None:
            digest = hashlib.sha256((kind + "|" + name).encode()).hexdigest()[:10]
            base = f"evidence/{qid}/{kind}-{slug(name)}-{digest}"
            item["path"] = base + ".raw"
            write_text(self.path(item["path"]), raw)
            item["sha256"] = hashlib.sha256(raw.encode()).hexdigest()
            item["bytes"] = len(raw.encode())
            if html:
                document = Document(raw)
                item["text_path"] = base + ".txt"
                write_text(self.path(item["text_path"]), document.command if kind == "command" else document.text)
        if error:
            item["error"] = error
        self.manifest["artifacts"][self.key(qid, kind, name)] = item
        self.save()
        return item

    def raw(self, qid, kind, name):
        item = self.item(qid, kind, name)
        return self.path(item["path"]).read_text() if item and item["status"] == "ok" else None

    def command(self, qid, name):
        raw = self.raw(qid, "command", name)
        return Document(raw).command if raw is not None else None

    def evidence(self, qid, kind, name):
        item = self.item(qid, kind, name)
        if not item:
            return {"qid": qid, "kind": kind, "name": name, "status": "not_collected"}
        return {k: item[k] for k in ("qid", "kind", "name", "status", "source_url", "text_path", "path", "error") if k in item}
