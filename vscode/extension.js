// Clawprint for VS Code — activity-bar sidebar showing the capability
// manifest, context weight, and manifest-check diff for the open workspace.
// All data comes from the clawprint CLI (--json); this file only orchestrates.
'use strict';

const path = require('node:path');
const vscode = require('vscode');
const { snapshot, runCli } = require('./runner');
const { CapabilitiesProvider, WeighProvider, CheckProvider, fmt } = require('./providers');

const WATCH_GLOB = '{**/.claude/**,CLAUDE.md,CLAUDE.local.md,.mcp.json,AGENTS.md,GEMINI.md,.cursorrules,.windsurfrules,.clinerules,.cursor/**,.github/copilot-instructions.md,.clawprint.json}';
const DEBOUNCE_MS = 600;

function activate(context) {
  const capabilities = new CapabilitiesProvider();
  const weigh = new WeighProvider();
  const check = new CheckProvider();

  context.subscriptions.push(
    vscode.window.registerTreeDataProvider('clawprint.capabilities', capabilities),
    vscode.window.registerTreeDataProvider('clawprint.weigh', weigh),
    vscode.window.registerTreeDataProvider('clawprint.check', check),
  );

  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 90);
  status.command = 'clawprint.refresh';
  context.subscriptions.push(status);

  const rootOf = () => vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? null;

  let refreshing = false;
  async function refresh() {
    const root = rootOf();
    if (!root || refreshing) return;
    refreshing = true;
    try {
      const snap = await snapshot(context, root);
      capabilities.update(snap, root);
      weigh.update(snap, root);
      check.update(snap, root);

      if (snap.weigh) {
        const tokens = snap.weigh.always.tokens;
        const budget = vscode.workspace.getConfiguration('clawprint').get('budget', 0);
        const over = budget > 0 && tokens > budget;
        status.text = `$(law) ~${fmt(tokens)} ctx tok${over ? ' — OVER BUDGET' : ''}`;
        status.tooltip = `Clawprint: ~${fmt(tokens)} tokens always loaded per session`
          + (budget > 0 ? ` (budget ${fmt(budget)})` : '')
          + ` — ${snap.report.items.length} agent-config item(s). Click to refresh.`;
        status.backgroundColor = over ? new vscode.ThemeColor('statusBarItem.warningBackground') : undefined;
        status.show();
      }
    } catch (err) {
      vscode.window.showErrorMessage(`Clawprint: ${err.message}`);
    } finally {
      refreshing = false;
    }
  }

  context.subscriptions.push(
    vscode.commands.registerCommand('clawprint.refresh', refresh),

    vscode.commands.registerCommand('clawprint.scanWrite', async () => {
      const root = rootOf();
      if (!root) return;
      const res = await runCli(context, root, ['--dir', root]);
      if (res.code === 0) {
        vscode.window.showInformationMessage('Clawprint: wrote CLAWPRINT.md + .clawprint.json — commit both.');
      } else {
        vscode.window.showErrorMessage(`Clawprint: ${res.stderr || res.stdout}`.trim());
      }
      await refresh();
    }),

    vscode.commands.registerCommand('clawprint.openManifest', async () => {
      const root = rootOf();
      if (!root) return;
      const uri = vscode.Uri.file(path.join(root, 'CLAWPRINT.md'));
      try {
        await vscode.window.showTextDocument(uri);
      } catch {
        vscode.window.showWarningMessage('No CLAWPRINT.md yet — run "Clawprint: Write Manifest" first.');
      }
    }),
  );

  // rescan on agent-config changes, debounced
  const watcher = vscode.workspace.createFileSystemWatcher(WATCH_GLOB);
  let timer = null;
  const schedule = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(refresh, DEBOUNCE_MS);
  };
  watcher.onDidChange(schedule);
  watcher.onDidCreate(schedule);
  watcher.onDidDelete(schedule);
  context.subscriptions.push(watcher, { dispose: () => timer && clearTimeout(timer) });
  context.subscriptions.push(vscode.workspace.onDidChangeWorkspaceFolders(refresh));

  refresh();
}

function deactivate() {}

module.exports = { activate, deactivate };
