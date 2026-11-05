# Migration Recommendation — F5 migration analysis skill

A global OpenCode skill plus a standard-library Python tool. Each new run starts with explicitly supplied QKViews and independent customer requirements. The reusable material contains no customer IDs, traffic baselines, or recommended model defaults.

## Install from GitHub

Requires Git, OpenCode, and Python 3.10+. The analysis tool uses the Python standard library; no pip/npm installation is needed.

```bash
git clone git@github.com:f5windswept/migration-recommendation.git
python3 migration-recommendation/install.py
```

The installer places the skill in `~/.config/opencode/skills/f5-migration/` and the command in `~/.config/opencode/commands/f5-migration.md`. Re-running it updates changed files and preserves previous versions of conflicting installed files in `~/.config/opencode/f5-migration-backups/`.

After pulling updates into your checkout, run `python3 install.py` from that checkout and restart OpenCode. If the checkout is already the installed skill directory, the installer leaves those source files in place and synchronizes the command.

### Repository layout

- `SKILL.md`: model workflow and interpretation instructions.
- `commands/f5-migration.md`: versioned `/f5-migration` command.
- `scripts/`: reusable collector, parsers, analysis, and CLI.
- `references/`: dated specifications and interpretation guidance.
- `templates/`: recommendation report structure.
- `tests/`: synthetic regression tests and explicit local replay adapter.
- `install.py`: global OpenCode installer.
- `.github/workflows/tests.yml`: Python 3.10/3.14 test and installation checks.

## Start in OpenCode

Quit and restart OpenCode after installation, then use:

```text
/f5-migration Customer: ExampleCo. QKViews: <new-id-1>, <new-id-2>. Target: LTM-only. Compare rSeries and VE.
```

Or ask naturally to use the F5 migration skill with an iHealth search URL. Be signed into iHealth in Firefox. The skill collects evidence, reads a compact brief, investigates exceptions, and writes a recommendation. Python itself does not call an LLM or approve a purchase.

## Direct CLI

Requires Python 3.10+; no pip/npm dependencies or browser-control extensions.

```bash
python3 ~/.config/opencode/skills/f5-migration/scripts/f5_migration.py --help
python3 ~/.config/opencode/skills/f5-migration/scripts/f5_migration.py doctor
```

New explicit-ID run (replace placeholders):

```bash
python3 ~/.config/opencode/skills/f5-migration/scripts/f5_migration.py analyze \
  --customer "ExampleCo" --qkviews NEW_ID_1 NEW_ID_2 \
  --target-modules ltm --deployment compare
```

New search-based run:

```bash
python3 ~/.config/opencode/skills/f5-migration/scripts/f5_migration.py analyze \
  --customer "ExampleCo" \
  --search-url "https://ihealth.f5.com/qkview-analyzer/?query=exampleco&showAll=true" \
  --requirements /path/to/intake.json
```

Example intake (unknowns are intentional):

```json
{
  "target_modules": ["ltm"],
  "deployment": "compare",
  "growth_factor": null,
  "deadline": null,
  "virtualization": null,
  "site_constraints": "Preserve existing independent HA groups",
  "notes": null
}
```

Without confirmed target modules, omit the option or use `null` in intake. No implicit LTM-only or growth assumption is made. `--days` supports 1, 7, or 30 (default 30). `--output` must point to a new or empty directory. Otherwise the tool creates a unique run under `~/Documents/F5-Migrations/<customer>/`.

Search retrieves all matching pages. A query may include multiple generations/devices; the analyzer flags repeated hostnames, but the analyst must choose the intended snapshot and customer scope. Search never silently selects only the first page.

Retry THIS run after restoring Firefox access:

```bash
python3 ~/.config/opencode/skills/f5-migration/scripts/f5_migration.py resume --run "/path/to/run"
```

Change only THIS run's target requirements, with no network collection:

```bash
python3 ~/.config/opencode/skills/f5-migration/scripts/f5_migration.py summarize \
  --run "/path/to/run" --target-modules ltm --growth-factor 2
```

This saves intake history and regenerates evidence outputs. It does not overwrite the authored `report.md`; ask the assistant to update that report. New QKViews always require a new `analyze` run.

Targeted inspection:

```bash
python3 ~/.config/opencode/skills/f5-migration/scripts/f5_migration.py inspect \
  --run "/path/to/run" --qid NEW_ID --section modules --name ASM
```

Use `--firefox-profile "/path/to/profile"` if automatic discovery picks the wrong profile, and `--firefox-container N` for a Firefox container. macOS, Linux, and Windows profile locations are supported; macOS is the locally verified platform. Credentials are restricted to the iHealth origin, held in memory, never logged, and temporary cookie-database copies are deleted automatically. Firefox is not modified.

Exit codes: **0** for successful processing; **2** for errors/partial collection. Missing/unavailable commands remain explicit evidence gaps even when the tool completes. Resume checks evidence hashes and rejects changed/mixed runs. An existing nonempty output directory is never silently reused.

## Outputs and token efficiency

- `intake.json` / `intake-history.json`: this run's requirements.
- `run.json`: identity, exact ID set, collection state, source URLs, timestamps, artifact hashes.
- `evidence-summary.md`: compact model-facing brief; read this first.
- `findings.json`: detailed exceptions with evidence references.
- `evidence-summary.json`: complete structured analysis.
- `analysis/<qid>/device-summary.json`: per-device drill-down.
- `evidence-index.json`: raw/text paths and retrieval status.
- `evidence/<qid>/`: retrieved source artifacts; no global/customer-shared evidence cache.
- `report-outline.md`: reporting structure; the assistant authors `report.md`.

Raw graph samples and configuration are processed locally, not sent through model prompts by this tool. Only the compact brief and selected exceptions need model context. Artifacts are cached only within the explicitly resumed run. Authentication and command discovery are reused as code, even when every QKView is new.

## Implementation and verification

`scripts/f5m/` separates Firefox authentication, restricted transport, run storage, parsing, collection, analysis, and outputs. `references/platforms.json` is a dated reference catalog, not a live SKU feed. See `references/interpretation.md` for coverage and sizing limitations.

Run synthetic regression tests:

```bash
python3 -m unittest discover -s tests -v
```

Run this from the repository root. GitHub Actions runs the same tests and an installation smoke test. These checks use synthetic data and do not require an iHealth login.

`tests/replay_local.py` can validate against an explicitly supplied directory of the original collector's artifacts without logging in. It is a development-only adapter and never automatically loads an old customer. No customer artifacts are bundled with the skill.
