# code-reviewer memory — clawprint

## Project conventions
- Zero-dependency single-file ESM, Node >=20. Never suggest adding deps.
- Heuristic/regex extraction is deliberate and documented as a non-goal to bypass.
- Descriptive-never-judgmental: no severity scores, no "malicious" wording.
- Byte-determinism is a hard requirement: codepoint sort, no timestamps, LF-normalized output.
- SARIF all-`note` level is a deliberate design choice, not a bug.
- `unit.startLine + lineOf(unit.text, m.index) - 1` is the correct line-number formula for regex-based extractors; `unit.startLine + idx` is correct for line-by-line forEach loops.

## Known issues found in v0.2.0 review (2026-07-15)
- **MEDIUM** `clawprint.mjs:512` — Installs extractor prompt-stripping regex misses full PowerShell path prompt `PS C:\Users\>`. Commands extractor (line 471) has the full pattern; installs extractor does not. Causes false negatives when documentation fences show full PS prompts.
- **MEDIUM** `clawprint.mjs:832` — Duplicate `cursor-rules/{name}` item IDs when `.cursor/rules/` contains same-basename files with different extensions (e.g., `deploy.md` + `deploy.mdc`). `compareReports` uses a Map keyed by id so the second item silently shadows the first; capabilities in the first item become invisible to the check command.
- **LOW** `clawprint.mjs:418` — `cleanPackageSpec('.')` returns `'.'`. `pip install .` and `pip install -e .` extract `.` as an install name.
- **LOW** `clawprint.mjs:391/416` — `winget install --source <source> <pkg>` extracts the source name as a package because `--source` is not in INSTALL_ARG_FLAGS and the source name doesn't start with `-`.
- **LOW** `clawprint.mjs:1032` — SARIF `artifactLocation` lacks `uriBaseId: "%SRCROOT%"`. Low impact for typical GitHub Action use (repo root = scan root), but incorrect for subdirectory scans.
- **LOW** `clawprint.mjs:1254` — `--sarif` flag silently ignored when combined with `check` mode; no error or warning emitted.

## Tests
- All 49/50 tests pass (1 skipped: symlinks require admin on Windows).
- `--selftest` passes.
