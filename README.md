# clawprint

**The capability manifest for your `.claude/` directory. Know exactly what your
agent setup can do, and catch every change in PR review.**

`terraform plan` for your agent config: deterministic, zero-dependency, no AI,
no verdicts.

[![CI](https://github.com/vanara-agents/clawprint/actions/workflows/ci.yml/badge.svg)](https://github.com/vanara-agents/clawprint/actions/workflows/ci.yml)

An innocent-looking "docs update" PR touches a skill. The content hash changed —
of course it did, that's what updates do. What the hash can't tell you is that
the skill can now reach a new host. Clawprint can:

```diff
 ## skills/pdf-helper   `sha256:fa88551512a8…`
 - tools: Bash (.claude/skills/pdf-helper/SKILL.md), Read (…), WebFetch (…)
-- network: api.example-evil.test (.claude/skills/pdf-helper/SKILL.md)
+- network: api.example-evil.test (.claude/skills/pdf-helper/SKILL.md), api.pastebin-mirror.test (.claude/skills/pdf-helper/SKILL.md)
```

And in CI, on the same PR:

```
+ [skills/pdf-helper] network: api.pastebin-mirror.test

clawprint check: FAIL — new capabilities or content drift detected.
```

Don't take the README's word for it — run the bundled fixture tests yourself:

```
npx clawprint --selftest
```

## The gap

The agent-config trust space has three occupied niches and one that was empty:

| Niche | Question it answers | Examples |
|---|---|---|
| Security scanners | "Is this skill malicious?" (verdicts at install time) | snyk/agent-scan, ai-skill-scanner |
| Content lockfiles | "Did the bytes change?" | skills-lock |
| Eval harnesses | "Does this skill improve output?" | skill-eval-harness, skillcheck |
| **Capability manifest + diff** | **"What can my setup DO, and what did this PR change about that?"** | **clawprint** |

A skill that adds one `curl` to a new host in an innocent-looking "docs update"
PR sails through every content-hash tool — the hash is simply regenerated with
the PR. Scanners judge at install time; nothing watches **change-over-time at
the capability level**. That's clawprint's job.

## Quickstart

```bash
npx clawprint            # scan → writes CLAWPRINT.md + .clawprint.json
git add CLAWPRINT.md .clawprint.json && git commit -m "chore: add clawprint manifest"
npx clawprint check      # exit 1 if capabilities changed since the commit
```

From then on, every PR that changes what your agent setup *can do* shows up as
a reviewable diff in `CLAWPRINT.md` — and `check` fails CI until the manifest
is regenerated and the change is consciously committed.

### No npm required

The whole tool is one stdlib-only file, so the npm registry is a convenience,
not a dependency. All of these work with nothing but Node ≥ 20:

```bash
# run straight from GitHub via npx (git fetch, no registry)
npx github:vanara-agents/clawprint

# or download the single file and run it — that's the entire tool
curl -fsSL https://raw.githubusercontent.com/vanara-agents/clawprint/main/clawprint.mjs -o clawprint.mjs
node clawprint.mjs --selftest
node clawprint.mjs

# or clone it
git clone https://github.com/vanara-agents/clawprint && node clawprint/clawprint.mjs
```

The GitHub Action below never touches npm either — it runs the checked-out
file directly. If you vendor `clawprint.mjs` into your repo, you can read
every line of what you're trusting first, which is rather the point.

### GitHub Action

```yaml
name: agent-config
on:
  pull_request:
    paths: ['.claude/**', '.mcp.json', 'CLAUDE.md', 'CLAWPRINT.md', '.clawprint.json']
jobs:
  clawprint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vanara-agents/clawprint@main
```

### CLI

```
npx clawprint                  # scan → write CLAWPRINT.md + .clawprint.json, print summary
npx clawprint check            # rescan → compare to committed manifest → exit 0/1 + human diff
npx clawprint diff             # alias of check
npx clawprint --dir <path>     # scan a different root (works with all modes)
npx clawprint --json           # print the JSON report to stdout, write nothing
npx clawprint --selftest       # run bundled fixture tests, exit 0/1
npx clawprint check --allow-content-drift   # content-only changes become a note, not a failure
```

**`check` semantics** (the CI gate):

- **New capability** (host, command, env var, tool grant, outside write, opaque
  block, or whole item) → **exit 1**, printed as `+ [skills/foo] network: api.evil.test`
- **Removed capability** → exit 0, printed as `- …` (removals are safe; still noted)
- **Content-only change** (same capabilities, different bytes) → exit 1 by
  default — the instructions changed even if capabilities didn't, and a reviewer
  should glance. `--allow-content-drift` downgrades this to a note.
- **No manifest committed yet** → exit 1 with instructions.

## What it scans

Everything agent-shaped under a project root: `.claude/skills/**`,
`.claude/agents/**`, `.claude/commands/**`, `.claude/settings.json` +
`settings.local.json` (hooks and permission allowlists), `.mcp.json` (server
commands and URLs), and `CLAUDE.md` / `CLAUDE.local.md`. Missing directories
are fine.

## What it extracts

| Kind | What it captures | How |
|---|---|---|
| `tools` | Declared tool grants | `tools:` / `allowed-tools:` frontmatter in markdown |
| `commands` | Shell commands invocable | Code fences, `.sh`/`.mjs`/`.py` scripts, hook command strings, MCP server commands (`npx -y pkg` also surfaces `pkg`) |
| `network` | Hosts it can reach | URLs anywhere, `curl`/`wget`/`fetch`/`Invoke-WebRequest` targets, bare IPs — reported as unique hosts (full URL kept in the JSON) |
| `env` | Environment variables read | `$VAR`, `%VAR%`, `$env:VAR`, `process.env.X`, `os.environ[...]` — minus a small noise list (PATH, HOME, …) |
| `paths` | Writes **outside** the project | Redirects, `cp`/`mv`/`tee` targets, `writeFile`, `open(…, "w")`, `Set-Content` — only when the target starts with `~`, `/`, a drive letter or `%VAR%`. Project-relative writes are normal and not reported |
| `opaque` | Opaque content | Base64/hex runs ≥ 40 chars, zero-width and bidi-control unicode |
| `hash` | Content identity | sha256 per file + one hash per item — quietly covers the lockfile niche too |

Every finding is descriptive: clawprint reports *"skill X can reach
api.example.test"* — it never says "malicious". The human reading the diff
makes the call. No AI, no network calls, no verdicts, runs air-gapped.

## Determinism

Same input tree → byte-identical output, on every OS. No timestamps, sorted
everything, CRLF normalized on read, `\n` on write. The committed manifest
produces clean, reviewable git diffs — that's the whole point. CI enforces
this on Ubuntu and Windows for every push.

## Honest limits

Clawprint is static heuristics — grep with opinions, not a parser, not a
sandbox, and **not a security scanner**:

- A determined attacker can hide from regex (string-building at runtime,
  encodings we don't decode, dynamic imports). The `opaque` extractor flags
  the cheap tricks, not all of them.
- It reports what config *says* it can do, not what the runtime will allow or
  what an agent will actually decide to do.
- It doesn't judge. `network: api.example.test` might be your own API or an
  exfiltration endpoint — clawprint can't know, and doesn't pretend to.

Pair it with a security scanner at install time. Clawprint's job is making
**change visible in review**, not proving absence of malice. See
[SECURITY.md](SECURITY.md) for the full threat-model discussion.

## Contributing

Extractors are the contribution surface — each one is a single entry in the
`EXTRACTORS` array with a fixture and a test. See
[CONTRIBUTING.md](CONTRIBUTING.md). Good first issues: pip-install detection,
PowerShell download cradles, `.cursor/` and Codex directory support, SARIF
output.

## License

Apache-2.0.

---

Built by [Vanara](https://vanaraagents.com) — verified agents & skills for
Claude Code. Clawprint is the standalone version of the trust-step in
`npx vanara install`.
