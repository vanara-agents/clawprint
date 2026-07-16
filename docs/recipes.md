# Recipes

Practical ways to use clawprint beyond the basic PR gate. Everything here is
just the CLI plus standard tools — no plugins, no config files.

---

## 1. Pre-install trust check

Before you install a skill/agent from GitHub, read what it *can do* before it
ever lands in your `.claude/`:

```bash
git clone https://github.com/someone/cool-skill /tmp/cool-skill
npx clawprint --dir /tmp/cool-skill --json | less
```

You'll see every host it can reach, every command it runs, every secret it
reads, and any packages it installs at runtime — the install-time complement
to the PR-time gate, same tool, pointed earlier.

Prefer a human-readable page? Drop the `--json`:

```bash
npx clawprint --dir /tmp/cool-skill   # writes CLAWPRINT.md you can just read
```

---

## 2. Policy gate — fail on capabilities you don't allow

clawprint stays descriptive (it never says "bad"), but its JSON is machine
truth, so *you* can layer policy on top with a one-liner. These exit non-zero
when a rule is violated — drop any of them into CI after `npx clawprint`.

**Block network hosts not on an allowlist** (`jq` required):

```bash
ALLOW='api.github.com,registry.npmjs.org'
npx clawprint --json \
  | jq -e --arg allow "$ALLOW" '
      ($allow | split(",")) as $ok
      | [ .items[].findings[] | select(.kind=="network") | .value ]
      | map(select(. as $h | ($ok | index($h) | not)))
      | if length>0 then "Disallowed hosts: \(.)" | halt_error(1) else empty end
    '
```

**Fail if any skill reads cloud credentials:**

```bash
npx clawprint --json \
  | jq -e '[ .items[].findings[]
             | select(.kind=="env" and (.value|test("AWS_|AZURE_|GCP_|GOOGLE_")))
           ] | if length>0 then "Cloud creds read: \(map(.value))" | halt_error(1) else empty end'
```

**Fail on any runtime package install** (you may want installs to be explicit,
vetted, and pinned — not buried in a skill):

```bash
npx clawprint --json \
  | jq -e '[ .items[].findings[] | select(.kind=="installs") ]
           | if length>0 then "Runtime installs found: \(map(.value)|unique)" | halt_error(1) else empty end'
```

The judgment stays yours; clawprint just makes it enforceable.

---

## 3. Post the capability diff as a PR comment

Instead of only failing CI, surface the `+`/`-` diff where reviewers read.
This workflow comments on the PR whenever capabilities changed:

```yaml
name: clawprint-comment
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - name: Diff capabilities
        id: diff
        run: |
          OUT="$(npx --yes github:vanara-agents/clawprint check || true)"
          echo "changed=$([ -n "$OUT" ] && echo true || echo false)" >> "$GITHUB_OUTPUT"
          { echo 'body<<EOF'; echo "$OUT"; echo 'EOF'; } >> "$GITHUB_OUTPUT"
      - name: Comment
        if: steps.diff.outputs.changed == 'true'
        uses: actions/github-script@v7
        with:
          script: |
            const body = `### 🐾 clawprint — agent capability changes\n\n\`\`\`\n${{ toJSON(steps.diff.outputs.body) }}\n\`\`\``;
            github.rest.issues.createComment({
              owner: context.repo.owner, repo: context.repo.repo,
              issue_number: context.issue.number, body,
            });
```

Pair it with the blocking gate (the plain Action in the README) if you want
both a comment *and* a required check.

---

## 4. SARIF → GitHub Security tab

Surface findings in the same dashboard as CodeQL, for free:

```yaml
name: clawprint-sarif
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  sarif:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npx --yes github:vanara-agents/clawprint --sarif > clawprint.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: clawprint.sarif
```

Every finding lands as a `note`-level result under a `clawprint/<kind>` rule.
clawprint is descriptive, so nothing ranks higher than `note` — the point is
visibility, not a severity verdict.

---

## 5. When did a capability appear? (forensics)

Because the manifest is committed, git already knows:

```bash
# every commit that changed the manifest, newest first
git log --oneline -- CLAWPRINT.md

# what changed in each
git log -p -- CLAWPRINT.md

# find the exact commit that introduced a capability, automatically
git bisect start HEAD <last-known-good>
git bisect run sh -c 'npx clawprint check'
```

`git bisect run` flips each commit and re-checks; it stops on the one where
the capability first appeared — no manual hunting.

---

## 6. Version-over-version skill diff

"What did upgrading this skill actually change about what it can do?"

```bash
git checkout v1.2 && npx clawprint --dir . --json > /tmp/before.json
git checkout v1.3 && npx clawprint --dir . --json > /tmp/after.json
diff <(jq -S . /tmp/before.json) <(jq -S . /tmp/after.json)
```

A capability changelog the author never had to write.

---

## 7. Org-wide agent inventory ("SBOM for agents")

Aggregate every repo's committed `.clawprint.json` and you can answer
governance questions centrally — *which repos have agents that reach the
internet? which read cloud creds? what changed this week?*

```bash
# collect .clawprint.json from every repo checked out under ./repos
for d in repos/*/; do
  [ -f "$d/.clawprint.json" ] && jq --arg repo "$(basename "$d")" \
    '{repo:$repo, hosts:[.items[].findings[]|select(.kind=="network").value]|unique}' \
    "$d/.clawprint.json"
done | jq -s 'sort_by(.repo)'
```

The per-repo groundwork is already the committed manifest — this just rolls
it up.

---

**A note on all of the above:** clawprint reports what config *declares* it can
do, using static heuristics. It's the visibility layer, not a sandbox or a
verdict engine — see [SECURITY.md](../SECURITY.md) for the honest limits.
