// Runs the clawprint CLI and returns parsed results. The extension never
// reimplements scanning — the CLI (--json) is the single source of truth.
'use strict';

const { execFile } = require('node:child_process');
const { existsSync } = require('node:fs');
const path = require('node:path');
const vscode = require('vscode');

/** Resolve clawprint.mjs: setting > workspace node_modules > bundled vendor copy. */
function resolveCli(context, workspaceRoot) {
  const configured = vscode.workspace.getConfiguration('clawprint').get('cliPath', '');
  if (configured && existsSync(configured)) return configured;
  if (workspaceRoot) {
    const local = path.join(workspaceRoot, 'node_modules', 'clawprint', 'clawprint.mjs');
    if (existsSync(local)) return local;
    // monorepo dev convenience: the CLI beside this extension's folder
    const sibling = path.join(workspaceRoot, 'clawprint.mjs');
    if (existsSync(sibling)) return sibling;
  }
  return context.asAbsolutePath(path.join('vendor', 'clawprint.mjs'));
}

/** Run the CLI once. Resolves {code, stdout, stderr}; rejects only on spawn failure. */
function runCli(context, workspaceRoot, args) {
  const cli = resolveCli(context, workspaceRoot);
  return new Promise((resolvePromise, reject) => {
    execFile(
      process.execPath,
      [cli, ...args],
      {
        cwd: workspaceRoot,
        maxBuffer: 64 * 1024 * 1024,
        windowsHide: true,
        // In the desktop extension host process.execPath is the Electron
        // (Code.exe) binary, not node. Without this it launches a GUI window
        // instead of running the script, so stdout is empty and every report
        // parses to null (silent, error-free empty views). This makes Electron
        // execute as node; real-node hosts ignore it.
        env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
      },
      (error, stdout, stderr) => {
        if (error && error.code === undefined) return reject(error); // spawn failure, not exit code
        resolvePromise({ code: error ? error.code : 0, stdout, stderr });
      },
    );
  });
}

/** One full snapshot: capability report, weigh report, and check diff. */
async function snapshot(context, workspaceRoot) {
  const dirArgs = ['--dir', workspaceRoot];
  const [scan, weigh, check] = await Promise.all([
    runCli(context, workspaceRoot, ['--json', ...dirArgs]),
    // --global adds the ~/.claude tier and the per-session total (report.session)
    runCli(context, workspaceRoot, ['weigh', '--json', '--global', ...dirArgs]),
    runCli(context, workspaceRoot, ['check', ...dirArgs]),
  ]);
  const parseOr = (res, fallback) => {
    try {
      return JSON.parse(res.stdout);
    } catch {
      return fallback;
    }
  };
  return {
    report: parseOr(scan, { version: '?', items: [] }),
    weigh: parseOr(weigh, null),
    check: {
      code: check.code,
      lines: (check.stdout + check.stderr).split('\n').map((l) => l.trimEnd()).filter(Boolean),
      hasManifest: !/no \.clawprint\.json found/i.test(check.stdout + check.stderr),
    },
  };
}

module.exports = { resolveCli, runCli, snapshot };
