# Contributing to clawprint

Thanks for helping make agent-config changes visible. The bar for the core
tool is deliberately strict; the surface for contributions is deliberately
simple.

## Ground rules (non-negotiable)

1. **Zero dependencies.** Plain Node ≥ 20, ESM, stdlib only. PRs that add a
   dependency — including devDependencies — will be declined. The entire tool
   stays one readable file (`clawprint.mjs`).
2. **Deterministic or it's worthless.** Same input tree → byte-identical
   output. No timestamps, no randomness, no locale-dependent formatting,
   sorted everything. CI checks this on Ubuntu and Windows.
3. **Descriptive, never judgmental.** Findings state what config can do
   ("network: api.example.test"), never a verdict ("malicious", "risky",
   severity scores). Wording matters: "opaque content", not "obfuscated
   payload".
4. **No network calls, ever.** The tool must run air-gapped.
5. **Defanged fixtures only.** Never put live-format secrets in fixtures —
   even fake ones (GitHub push protection will block the push, and scanners
   will flag the repo). Use `.test` TLDs / `example-evil.test` domains and
   RFC 5737 IPs (`203.0.113.x`, `198.51.100.x`), never real hosts.

## The extractor pattern (the main contribution surface)

Each extractor is one entry in the `EXTRACTORS` array in `clawprint.mjs`:

```js
{
  id: 'my-extractor',            // becomes the finding `kind`
  description: 'What it captures, one line',
  run(text, relPath, ctx) {
    // pure function: never touch the filesystem, network, clock or globals.
    // `text` is LF-normalized file content; `ctx` gives you pre-computed
    // shell regions (ctx.shellUnits), markdown fences (ctx.fences), the
    // file extension (ctx.ext) and parsed JSON (ctx.json) when applicable.
    return [{ kind: 'my-extractor', value: '…', file: relPath, line: 1 }];
  },
}
```

Rules for a good extractor PR — **one extractor per PR**:

1. **Plant the signal in `fixtures/spicy`** (defanged!) and confirm
   `fixtures/clean` stays silent.
2. **Add a test** in `test/clawprint.test.js` asserting both.
3. **Regenerate the fixture manifests** (CI diffs them):
   ```bash
   node clawprint.mjs --dir fixtures/clean
   node clawprint.mjs --dir fixtures/spicy
   ```
4. **Keep values diff-friendly.** The finding `value` is what reviewers see
   in `CLAWPRINT.md` diffs — short, stable, no absolute paths from the
   scanning machine, no volatile content.
5. **Prefer missing a clever case over flooding output.** False positives
   train people to ignore the manifest; a documented limitation in
   SECURITY.md is better than noise.

Wanted extractors (good first issues): `pip install` / `uv add` detection,
PowerShell download cradles (`iex (iwr …)`), `.cursor/` and Codex directory
support, SARIF output mode.

## Running the checks

```bash
node --test                 # full suite
node clawprint.mjs --selftest   # embedded fixture subset (what the Action gates on)
node clawprint.mjs check --dir fixtures/clean
node clawprint.mjs check --dir fixtures/spicy
```

All four must pass on your machine before you open the PR; CI repeats them on
Ubuntu and Windows across Node 20/22/24.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`). Keep the
subject under ~70 chars; explain *why* in the body when it isn't obvious.
