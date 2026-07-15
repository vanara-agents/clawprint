# CLAWPRINT — build spec (v1, 2026-07-15)

> **For the fresh Claude Code session building this:** this file is the complete brief.
> It was written after real market research (sources inline) and carries hard-won lessons
> from the Vanara launch week. Follow it closely — especially **Non-goals** and
> **Launch rules**, which encode mistakes we already paid for once.

---

## One-liner

**`clawprint` — the capability manifest for your `.claude/` directory. Know exactly what
your agent setup can do, and catch every change in PR review.**

`terraform plan` for your agent config: deterministic, zero-dependency, no AI, no verdicts.

## The verified gap (why this deserves to exist)

Researched 2026-07-15. The agent-config trust space has three occupied niches and one empty one:

| Niche | Question it answers | Who's there |
|---|---|---|
| Security scanners | "Is this skill malicious?" (AI verdicts at install) | snyk/agent-scan, ai-skill-scanner, claude-skill-antivirus, Claude Code built-in auditor |
| Content lockfiles | "Did the bytes change?" | luisalima/skills-lock, pcomans/skills-lock |
| Eval harnesses | "Does this skill improve output?" | adewale/skill-eval-harness, skillcheck |
| **Capability manifest + diff** | **"What can my setup DO, and what did this PR change about that?"** | **Nobody.** Exists only as an unbuilt suggestion (awesome-claude-code issue #1869) |

Context making this timely: Snyk's ToxicSkills study found prompt injection in 36% of
skills tested and 1,467 malicious payloads; the ClawHavoc campaign shipped hundreds of
malicious skill packages. Scanners answer install-time. Nothing watches **change-over-time
at the capability level** — a skill that adds one `curl` to a new host in an innocent-looking
"docs update" PR sails through every content-hash tool if the hash is simply regenerated.

## Positioning (memorize this; it drives every decision)

- **Descriptive, never judgmental.** clawprint reports "skill X can reach api.evil.com" —
  it NEVER says "malicious". The human reading the diff makes the call. This is the moat
  vs. scanners: no false-positive arguments, no AI, no model bill, runs offline, output
  is stable enough to commit.
- **Deterministic or it's worthless.** Same input tree → byte-identical output. No
  timestamps in the manifest, no random ordering, sorted everything. The committed
  manifest must produce clean, reviewable git diffs.
- **Zero dependencies, single-file core.** Plain Node ≥ 20, ESM, stdlib only. One
  `clawprint.mjs` people can read end-to-end. (Trust tool that asks you to `npm install`
  40 packages is a joke that writes itself.)

## What it scans (v1 targets, all under a project root)

1. `.claude/skills/**` — `SKILL.md` + all support files (scripts/, references/, examples/)
2. `.claude/agents/**` — `<name>.md` + packaged dirs
3. `.claude/commands/**` — command markdown files
4. `.claude/settings.json` + `.claude/settings.local.json` — **hooks** (command strings) and permissions allowlists
5. `.mcp.json` (project MCP config) — server commands, args, URLs
6. `CLAUDE.md` / `CLAUDE.local.md` — scanned for the same signals, reported under item "claude-md"

Missing dirs are fine (empty report section). `--dir <path>` overrides root; default cwd.

## Extractors (the heart — each is a pure function: text/path → sorted findings)

For every file of every item, run all extractors; aggregate per item, dedupe, sort.

| # | Extractor | What it captures | Heuristics (v1) |
|---|---|---|---|
| E1 | `tools` | Declared tool grants | Frontmatter `tools:` / `allowed-tools:` lists in .md files (YAML-lite parse: the vanara frontmatter.js approach, ~40 lines, no YAML dep) |
| E2 | `commands` | Shell commands invocable | In code fences of .md + in .sh/.mjs/.js/.py scripts: first token of lines in `bash`/`sh` fences; `execSync`/`spawn`/`execFile`(JS), `subprocess`/`os.system`(Py) call args; hook command strings; MCP server `command` fields. Report the binary name + one-line context |
| E3 | `network` | Hosts it can reach | URLs anywhere (`https?://host`), `curl`/`wget`/`fetch`/`Invoke-WebRequest` targets, bare IPs. Report unique hosts, not full URLs (hosts diff cleaner; full URL in the JSON) |
| E4 | `env` | Env vars read | `$VAR`/`${VAR}` in shell contexts, `process.env.X`, `os.environ[...]`/`.get(...)`. Exclude a small builtin noise list (PATH, HOME, PWD, SHELL, TERM, USER) |
| E5 | `paths` | Writes outside the project | Write-ish operations (`>`, `>>`, `writeFile`, `open(..,'w')`, `Set-Content`, `cp`/`mv` targets) whose target starts with `~`, `/`, a Windows drive, or `%VAR%`. Project-relative writes are NOT reported (that's normal behavior) |
| E6 | `opaque` | Obfuscation surface | Base64 runs ≥ 40 chars, hex runs ≥ 40 chars, and any zero-width/bidi unicode (U+200B-200F, U+202A-202E, U+2060-2064, U+FEFF mid-file). Wording in output: "opaque content", never "obfuscated payload" — descriptive, remember |
| E7 | `hash` | Content identity | sha256 per file + one item-level hash (sorted `path:hash` lines — reuse the exact recipe from vanara `integrity.js`). This quietly covers the lockfile niche too |

Every finding records `{kind, value, file, line}` in JSON; the MD manifest shows
`kind: value (file)` — line numbers only in JSON (line numbers in MD would make diffs noisy
when unrelated lines shift — determinism rule).

**Extractors are the contribution surface.** Each lives as one entry in an `EXTRACTORS`
array with `{id, description, run(text, relPath, context)}`. Adding one = a good-first-issue.

## CLI surface

```
npx clawprint                  # scan → write CLAWPRINT.md + .clawprint.json, print summary
npx clawprint check            # rescan → compare to committed manifest → exit 0/1 + human diff
npx clawprint diff             # alias of check
npx clawprint --dir <path>     # scan a different root (works with all modes)
npx clawprint --json           # print the JSON report to stdout, write nothing
npx clawprint --selftest       # run bundled fixture tests, exit 0/1
```

### `check` semantics (the CI gate)

- **New capability** (new host, new command, new env var, new tool grant, new outside-path,
  new opaque block, new item) → **exit 1**, printed as `+ [skill/foo] network: api.evil.com`
- **Removed capability** → exit 0, printed as `- ...` (removals are safe; note them)
- **Hash-only change** (same capabilities, different content) → exit 1 by default,
  `--allow-content-drift` downgrades to a note. Rationale: instructions changed even if
  capabilities didn't; reviewer should glance.
- No manifest committed yet → exit 1 with "run `npx clawprint` and commit the result."

## Output files

**`CLAWPRINT.md`** (committed, human-reviewed) — deterministic layout:

```markdown
# Clawprint — agent capability manifest
<!-- generated by clawprint vX.Y.Z — do not hand-edit; regenerate with: npx clawprint -->

## Summary
| Items | Commands | Network hosts | Env vars | Outside writes | Opaque blocks |
|---|---|---|---|---|---|
| 12 | 9 | 3 | 4 | 1 | 0 |

## skills/secret-scanner   sha256:ab12cd34…
- commands: node (scripts/scan.mjs), grep (SKILL.md)
- network: (none)
- env: GITHUB_TOKEN (scripts/scan.mjs)
...
```

Items sorted by path; findings sorted by kind then value. Version line contains the tool
version but **no timestamp**.

**`.clawprint.json`** (committed, machine truth for `check`): schema
`{version, items: [{id, kind, files: {path: sha256}, itemHash, findings: [{kind, value, file, line}]}]}` —
sorted, 2-space, trailing newline.

## Repo layout

```
clawprint/
├── clawprint.mjs            # entire tool (~600-800 lines target, single file)
├── action.yml               # composite GitHub Action: runs `check`, fails PR on new capabilities
├── package.json             # name clawprint, bin, zero deps, node>=20, MIT... see License note
├── .github/workflows/ci.yml # selftest + dogfood: clawprint check on this repo's own fixtures
├── fixtures/
│   ├── clean/.claude/...    # benign mini-tree: 2 skills, 1 agent, settings with a hook
│   └── spicy/.claude/...    # exercises EVERY extractor: fake host, env read, ~ write, base64 blob, zero-width char
├── test/clawprint.test.js   # node --test; see Testing
├── README.md                # see README skeleton
├── CONTRIBUTING.md          # extractor pattern how-to; one extractor per PR
├── SECURITY.md              # what this tool does/doesn't protect against (honest limits)
└── LICENSE                  # Apache-2.0 (matches vanara-agents org convention)
```

## Testing (non-negotiable bar)

`node --test`, no frameworks. Minimum:

1. **Per-extractor fixtures**: every extractor catches its planted signal in `fixtures/spicy`
   and stays silent on `fixtures/clean`.
2. **Determinism**: scan `fixtures/spicy` twice → byte-identical MD and JSON. Scan with
   files fed in reversed order → still identical.
3. **check semantics**: add a host to a fixture copy → exit 1 with `+` line; remove one →
   exit 0 with `-` line; content-only edit → exit 1, and 0 with `--allow-content-drift`.
4. **Selftest** (`--selftest`) runs an embedded subset so the GitHub Action can gate on it
   without the test dir.
5. CI = tests + dogfood (`clawprint check` against committed fixture manifests).

**Fixture rule (paid lesson):** never put live-format secrets in fixtures — even fake ones.
GitHub push protection will block, and scanners will flag the repo itself. Defang:
`ghp_` + `x.repeat(36)` at runtime, or split strings. Same for URLs: use `example.com` /
`api.example-evil.test`, never real domains.

## Non-goals (stay disciplined — scope creep kills the one-day ship)

- ❌ No AI calls, no network calls, ever. The tool must run air-gapped.
- ❌ No verdicts, severity scores, or "risk ratings". Descriptive only.
- ❌ No auto-fix, no auto-update of the manifest in CI (regenerating in CI defeats review).
- ❌ No YAML/AST parsing dependencies — heuristic extraction is fine and honest (see SECURITY.md limits).
- ❌ No config file in v1. Flags only. (Config = bikeshed magnet in week 1.)
- ❌ v1 scans `.claude/` + `.mcp.json` only. Cursor/Codex dirs are the roadmap (and great good-first-issues).

## README skeleton

1. Hero: one-liner + a **real PR diff screenshot** showing
   `+ [skills/pdf-helper] network: api.pastebin-mirror.test` caught in review
2. "The gap" table (scanners vs lockfiles vs clawprint — reuse the table above)
3. Quickstart (3 commands) + the GitHub Action snippet
4. What it extracts (the E1–E7 table, user-facing wording)
5. **Honest limits section**: static heuristics; a determined attacker can hide from regex;
   pair with a scanner at install-time; clawprint's job is making *change visible*, not
   proving absence of malice. (The trust-tool audience punishes overclaiming hardest —
   we know this from direct experience.)
6. Footer: "Built by [Vanara](https://vanaraagents.com) — verified agents & skills for
   Claude Code. Clawprint is the standalone version of the trust-step in `npx vanara install`."
   **One link, once.** The tool must never nag about Vanara in CLI output.

## Launch rules (encode the Vanara week's lessons — do not skip)

1. **Every claim publicly verifiable before posting.** No claim without a command the
   reader can run (`npx clawprint --selftest`) or a link to a green CI run. Badge → Actions
   run, never a static shield.
2. **Receipts inline**: the launch post includes the PR-diff screenshot. Never post without it.
3. **Disclosure-first**: "founder of Vanara, this is a free standalone tool" in the first
   lines. Concealing the connection would burn both brands.
4. **One subreddit** (r/ClaudeAI or the skills-focused sub), not a blast. X thread via the
   social queue (`social/queue/drafts/` in the monorepo). URL-free main tweets; links in replies.
5. Seed 4–6 good-first-issues at launch: new extractors (pip-install detection, PowerShell
   download cradles), Cursor `.cursor/` support, Codex support, a `--sarif` output.
6. Repo hygiene before the post: topics (`claude-code`, `agent-security`, `supply-chain`,
   `ai-agents`, `capability-manifest`), social preview image, Apache-2.0, the fixtures visible.

## Definition of done (today)

- [ ] `npx clawprint` on a real project (use the Vanara monorepo's `.claude/`) produces a
      correct, deterministic manifest
- [ ] `check` catches a planted new-host edit with exit 1 and a readable `+` line
- [ ] All tests green; CI green on first push; determinism test passes on Windows AND in
      ubuntu CI (watch CRLF — normalize to `\n` on read, write `\n` always)
- [ ] README complete with real screenshot; SECURITY.md limits written
- [ ] Published to npm as `clawprint` (verified free 2026-07-15) — `npx clawprint` must work cold
- [ ] Repo public under `vanara-agents/clawprint`, issues seeded, launch drafts queued (NOT posted — human posts)

## Context a fresh session won't have

- **Vanara**: $10/mo verified agents/skills catalog for Claude Code. Public free tier:
  github.com/vanara-agents/skills (29 items, 28/28 checks in public CI). CLI `vanara@0.7.0`
  just shipped the pre-install trust-step (file plan + sha256 + confirm; `vanara verify`).
  Clawprint is deliberately the same trust philosophy, generalized beyond Vanara installs.
- **Code style that worked all week**: zero-dep single-file ESM tools with `--selftest`
  flags, guarded so selftest only fires on direct run, not import (`realpathSync(argv[1])`
  vs `import.meta.url` — see checkpoint.mjs / x-client.mjs pattern). Reuse it.
- **Name check done 2026-07-15**: npm `clawprint` 404 (free). GitHub has unrelated small
  `clawprint` repos — fine. Claim npm early in the session.
- The wider trust arc this lands in: Reddit comment → trust-step CLI (0.7.0) → public CI
  badge → clawprint. The launch story writes itself: "third trust tool this week, and this
  one's for everyone's `.claude/`, not just ours."
```
