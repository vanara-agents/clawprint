# Security

## What clawprint is

Clawprint is a **change-visibility tool**, not a security scanner. It produces
a deterministic manifest of what an agent configuration (`.claude/`,
`.mcp.json`, `CLAUDE.md`) declares it can do — commands, network hosts,
environment variables, tool grants, outside-project writes, opaque content —
so that any change to those capabilities shows up as a reviewable diff and a
failing CI check.

It makes one promise: **a capability change that clawprint's extractors can
see will not silently pass review.** It deliberately makes no promise about
malice, intent, or safety.

## What clawprint protects against

- **Capability creep in review.** The core threat: a PR that looks like a
  docs tweak but adds a new network host, a new shell command, a new env-var
  read, or a write outside the project. Content-hash lockfiles can't catch
  this — the hash is simply regenerated with the PR. Clawprint diffs at the
  capability level, so the reviewer sees `+ network: api.pastebin-mirror.test`.
- **Silent instruction drift.** Even when capabilities are unchanged,
  `check` fails on content changes by default (downgradeable with
  `--allow-content-drift`), because changed instructions deserve a glance.
- **The cheap obfuscation tricks.** Long base64/hex runs and zero-width or
  bidi-control unicode are flagged as `opaque` findings — descriptively, so a
  human decides whether a config file has any business containing them.

## What clawprint does NOT protect against

Be honest with yourself about these before relying on it:

1. **Runtime string-building.** `const h = 'evil' + '.example' + '.com'` or a
   host assembled from char codes will not appear as a `network` finding.
   Static regex extraction cannot follow data flow. (The pieces may still
   trip other extractors — but don't count on it.)
2. **Encodings we don't decode.** Clawprint flags a base64 blob as opaque; it
   does not decode it, and it does not detect capabilities *inside* it. Same
   for compressed, encrypted, or novel encodings shorter than the 40-char
   threshold.
3. **Anything outside the scanned surface.** Binaries, node_modules, packages
   an MCP server downloads at runtime (`npx -y whatever` is reported as a
   command — what that package then does is invisible), remote content a
   skill instructs the agent to fetch.
4. **Prompt-injection semantics.** Clawprint reads config as text, not as
   instructions. A skill whose prose manipulates the agent without using any
   new capability will not fail `check` beyond content drift.
5. **A malicious collaborator regenerating the manifest.** `check` compares
   the tree to the *committed* manifest. If a PR both adds a capability and
   regenerates the manifest, CI goes green **by design** — the capability is
   now visible in the `CLAWPRINT.md` diff, and the human reviewer must read
   it. Clawprint moves the needle from "invisible" to "visible"; it cannot
   replace the reviewer. Protect the manifest with CODEOWNERS if you want a
   required second pair of eyes.
6. **Heuristic gaps.** The extractors are documented, tested heuristics — not
   parsers. Exotic quoting, line continuations and unusual syntax can slip
   past them. Extractor improvements are the main contribution surface.

## Complementary tools

Use clawprint **with**, not instead of:

- an install-time security scanner (verdict-oriented, catches known-bad
  patterns before anything lands in your tree),
- Claude Code's own permission system (runtime enforcement),
- ordinary code review (clawprint's entire job is to feed it better signal).

## Operational notes

- Clawprint makes **no network calls, ever**, and has **zero dependencies**.
  It runs air-gapped. `npx clawprint --selftest` verifies the extractors on
  bundled fixtures.
- Output is deterministic (no timestamps, sorted, LF-normalized), so the
  manifest is safe to commit and diff.
- The fixtures in this repo contain **defanged** signals only: `.test` /
  `example-evil.test` domains, RFC 5737 documentation IPs, base64 of a
  harmless sentence. No live secret formats, anywhere, including tests.

## Reporting a vulnerability

If you find a way to make a capability change invisible to clawprint's
extractors (an extraction bypass), please open a GitHub Security Advisory on
this repository — or an ordinary issue if the technique is already public.
Extraction bypasses are treated as bugs of the highest priority: the tool's
one promise is that visible-surface changes stay visible.
