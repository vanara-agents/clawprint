# Clawprint for VS Code

The [clawprint](https://github.com/vanara-agents/clawprint) capability
manifest, in your sidebar. A claw icon in the Activity Bar opens three views
for the open workspace:

- **Capabilities** — every agent-config item (skills, agents, commands,
  settings, `.mcp.json`, `CLAUDE.md`, Cursor/Codex/Gemini/Copilot files) with
  what it can do: tool grants, shell commands, runtime installs, network
  hosts, env vars read, writes outside the repo, opaque blocks. Click any
  finding to jump to its `file:line`.
- **Context Weight** — what the setup costs, grouped by when it enters the
  context window: always loaded (every session), on invoke, referenced files.
  Exact chars, labeled ~token estimates. Items with no description get a
  warning — they weigh nothing but may never be selected.
- **Manifest Check** — the live diff against your committed
  `.clawprint.json`: `+` new capability (red), `-` removed (safe),
  `~` content drift.

Plus a **status bar item** (`~6,893 ctx tok`) showing the always-loaded
weight, with an optional budget (`clawprint.budget`) that turns it into a
warning when exceeded. Views refresh automatically when agent-config files
change.

All data comes from the clawprint CLI run with `--json` — the extension
adds no scanning logic of its own, so the sidebar can never disagree with
your CI. Resolution order for the CLI: the `clawprint.cliPath` setting →
`node_modules/clawprint` in the workspace → the copy bundled with the
extension.

## Run it from source

```bash
cd vscode
npm run vendor        # copy ../clawprint.mjs into vendor/
code .                # then press F5 (Run Extension)
```

## Package a .vsix

```bash
cd vscode
npm run package       # runs vsce; install the .vsix via 'Extensions: Install from VSIX'
```
