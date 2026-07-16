# `clawprint weigh` — context-cost inventory (v0.3.0)

## Why

The capability manifest answers *what can this setup do*. `weigh` answers the
sibling inventory question: *what does this setup cost in context, every
session?* Agent configs accrete — CLAUDE.md grows, skills multiply — and the
cost is invisible until sessions feel slow or hit limits. Same clawprint
ethos: deterministic, descriptive, zero deps, no verdicts, offline.

## The honesty line

- **Character and byte counts are exact.** They lead every row.
- **Token figures are estimates** (`chars ÷ 4`, the industry rough constant),
  always labeled `~` and always derived from the exact counts shown beside
  them. Same input → same output; no tokenizer dependency, no network.
- **What we cannot measure offline, we say so** instead of guessing: MCP tool
  schemas load at runtime from the servers; hook commands run as shell (no
  context cost); how the host tool truncates or caches is its business.
- **No verdicts.** `weigh` never says "too big" on its own — the only
  pass/fail is `--budget N`, a threshold the *user* sets.

## Cost tiers

Files are grouped by *when* their content enters the context window:

| Tier | What | When it costs |
|---|---|---|
| `always` | CLAUDE.md + CLAUDE.local.md, full content; skills/agents/commands frontmatter `description` (their listing entry) | Every session, before the first prompt |
| `invoke` | The primary .md body of each skill/agent/command | Only when that item is used |
| `reference` | Every other file inside a skill/agent dir (references/, scripts/, fixtures) | Only if the agent reads it |
| `other` | Other-ecosystem files clawprint already discovers (AGENTS.md, .cursorrules, .cursor/rules, GEMINI.md, copilot-instructions.md, .clinerules, .windsurfrules) | Always — by *their* tool, not Claude Code |
| notes | .mcp.json (server count only), settings.json (hooks) | Stated as not measurable / not context |

Binary files in `reference` are listed by exact bytes with no token estimate.

### Global tier & per-session total (`--global`)

A project's `.claude/` is only part of the tax. The user's global `~/.claude`
config (its own CLAUDE.md + skill/agent/command descriptions) loads into
*every* session in *every* project, and is usually the larger share.

`--global` re-runs the same `always`-tier accounting against `~/.claude` (using
a "config sits directly under the root" layout instead of a nested `.claude/`)
and attaches two fields to the report:

- `global` — the `always`/`invoke` tiers computed for `~/.claude`.
- `session` — `{ globalAlwaysChars/Tokens, projectAlwaysChars/Tokens,
  totalChars, totalTokens }`, where `total = global.always + project.always`.
  `totalTokens` derives from summed exact **chars** (÷ 4), never from summing
  rounded per-tier token figures.

When the scanned project *is* `~/.claude`, the global tier is zeroed so the same
config is not counted once as project and again as global.

Deliberately **not** counted: plugin- or hook-injected context. A SessionStart
hook that emits rules at runtime (e.g. stack-conditional rule files) chooses its
payload at runtime — a static scan that summed the whole `rules/` tree would
over-report every language the user never loads. `weigh` flags this as
not-measurable rather than manufacturing a number.

## CLI

```
npx clawprint weigh              full report to stdout (writes no files)
npx clawprint weigh --top 10    show 10 heaviest invoke/reference items (default 5)
npx clawprint weigh --global    add the ~/.claude tier + total tokens per session
npx clawprint weigh --budget N  exit 1 if the estimate exceeds N tokens (per-session with --global)
npx clawprint weigh --brief     one line — made for hooks and statuslines
npx clawprint weigh --json      machine-readable report
```

`--dir` composes as with every other mode. `weigh` never writes files, so it
cannot disturb the committed manifest.

`--budget` is the CI hook: a PR that balloons the always-loaded context past
the team's chosen ceiling fails visibly, exactly like `check` does for
capabilities.

## The "preflight" idea (scoped honestly)

Requested: "before answering, tell the user estimated tokens and whether a
skill could save some." Split into what is and isn't honest to build:

- **Buildable now** — session-start awareness: a Claude Code `SessionStart`
  hook running `npx clawprint weigh --brief` prints the setup's standing cost
  the moment a session opens. Deterministic, honest, zero surprise. Shipped
  as a documented recipe in the README.
- **Not buildable honestly** — predicting tokens a specific *answer* will
  consume, or whether a given skill would net-save on a given prompt. That
  depends on model behavior at runtime; a deterministic tool printing such a
  number would be manufacturing false precision, which is the exact thing
  clawprint exists to avoid. If the host tool exposes real per-request
  accounting someday, that's its feature, not ours to fake.

## Determinism & tests

- `weigh` output is byte-identical for identical input trees, independent of
  file discovery order (same guarantee, same selftest pattern as scan).
- Selftest additions: known fixture → exact expected char totals; budget
  above/below threshold → exit 0/1; brief line stable.
- node --test additions mirror existing CLI tests against fixtures/spicy.
