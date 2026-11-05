#!/usr/bin/env python3
"""Install the reusable skill and command into OpenCode's global configuration."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import shutil
import uuid


ROOT_FILES = ("SKILL.md", "README.md")
DIRECTORIES = ("scripts", "references", "templates", "tests")


def install(source, config):
    source, config = Path(source).resolve(), Path(config).expanduser().resolve()
    target = config / "skills/f5-migration"
    files = [(source / name, target / name) for name in ROOT_FILES]
    for directory in DIRECTORIES:
        for path in sorted((source / directory).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix not in (".pyc", ".pyo"):
                files.append((path, target / path.relative_to(source)))
    files.append((source / "commands/f5-migration.md", config / "commands/f5-migration.md"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    backup = config / "f5-migration-backups" / stamp
    changed = saved = 0
    for original, destination in files:
        if not original.is_file():
            raise FileNotFoundError(f"Required project file is missing: {original}")
        if original.resolve() == destination.resolve():
            continue
        if destination.exists():
            if destination.read_bytes() == original.read_bytes():
                continue
            previous = backup / destination.relative_to(config)
            previous.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(destination, previous)
            saved += 1
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, destination)
        changed += 1
    return {"skill": target, "command": config / "commands/f5-migration.md",
            "changed": changed, "backup": backup if saved else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", default=str(Path.home() / ".config/opencode"),
                        help="Installation root; defaults to ~/.config/opencode")
    args = parser.parse_args()
    result = install(Path(__file__).parent, args.config_dir)
    print(f"Skill: {result['skill']}\nCommand: {result['command']}\nFiles updated: {result['changed']}")
    if result["backup"]:
        print(f"Previous changed files saved to: {result['backup']}")
    print("Quit and restart OpenCode to load the installed skill and command.")


if __name__ == "__main__":
    main()
