// Tree data providers for the three Clawprint sidebar views. Pure rendering:
// every provider consumes the last CLI snapshot and never scans anything itself.
'use strict';

const path = require('node:path');
const vscode = require('vscode');

const KIND_ICONS = {
  tools: 'tools',
  commands: 'terminal',
  installs: 'package',
  network: 'globe',
  env: 'key',
  paths: 'file-symlink-directory',
  opaque: 'eye-closed',
};

const fmt = (n) => n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');

class BaseProvider {
  constructor() {
    this._emitter = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._emitter.event;
    this.snapshot = null;
    this.workspaceRoot = null;
  }

  update(snapshot, workspaceRoot) {
    this.snapshot = snapshot;
    this.workspaceRoot = workspaceRoot;
    this._emitter.fire(undefined);
  }

  getTreeItem(element) {
    return element;
  }
}

const item = (label, opts = {}) => {
  const node = new vscode.TreeItem(label, opts.children
    ? vscode.TreeItemCollapsibleState.Collapsed
    : vscode.TreeItemCollapsibleState.None);
  if (opts.description) node.description = opts.description;
  if (opts.icon) node.iconPath = new vscode.ThemeIcon(opts.icon, opts.color ? new vscode.ThemeColor(opts.color) : undefined);
  if (opts.tooltip) node.tooltip = opts.tooltip;
  if (opts.command) node.command = opts.command;
  node._children = opts.children ?? null;
  return node;
};

/** Capabilities: item → finding kind (with count) → value (click = open file:line). */
class CapabilitiesProvider extends BaseProvider {
  getChildren(element) {
    if (element) return element._children ?? [];
    if (!this.snapshot) return [];
    return this.snapshot.report.items.map((it) => {
      const byKind = new Map();
      for (const f of it.findings) {
        if (!byKind.has(f.kind)) byKind.set(f.kind, []);
        byKind.get(f.kind).push(f);
      }
      const kindNodes = [...byKind.entries()].map(([kind, findings]) =>
        item(kind, {
          description: String(findings.length),
          icon: KIND_ICONS[kind] ?? 'circle-outline',
          children: findings.map((f) => this._findingNode(f)),
        }));
      return item(it.id, {
        description: it.kind,
        icon: it.kind === 'skill' ? 'book' : it.kind === 'agent' ? 'robot' : 'file-code',
        tooltip: `sha256:${it.itemHash.slice(0, 12)}… — ${it.findings.length} finding(s)`,
        children: kindNodes.length ? kindNodes : [item('no capabilities detected', { icon: 'check' })],
      });
    });
  }

  _findingNode(f) {
    const abs = path.join(this.workspaceRoot, f.file);
    return item(f.value, {
      description: `${f.file}:${f.line}`,
      icon: 'go-to-file',
      tooltip: f.detail ?? f.value,
      command: {
        command: 'vscode.open',
        title: 'Open',
        arguments: [
          vscode.Uri.file(abs),
          { selection: new vscode.Range(f.line - 1, 0, f.line - 1, 0) },
        ],
      },
    });
  }
}

/**
 * Token Usage: the headline per-session total, split into the global (~/.claude)
 * and project (this repo) always-loaded tiers. Populated from report.session,
 * which the extension requests with `weigh --global`.
 */
class SessionProvider extends BaseProvider {
  getChildren(element) {
    if (element) return element._children ?? [];
    const w = this.snapshot?.weigh;
    if (!w) return [];
    const s = w.session;
    const row = (label, chars, tokens, icon, tooltip) =>
      item(label, { description: `${fmt(chars)} chars · ~${fmt(tokens)} tok`, icon, tooltip });

    // Fallback for a CLI too old to emit report.session: show project always only.
    if (!s) {
      return [row(`Project — ~${fmt(w.always.tokens)} tokens/session`, w.always.chars, w.always.tokens, 'flame')];
    }
    return [
      row(`Per session — ~${fmt(s.totalTokens)} tokens`, s.totalChars, s.totalTokens, 'law',
        'Total context every session starts with: global + this project (before your first prompt)'),
      row(`Global (~/.claude)`, s.globalAlwaysChars, s.globalAlwaysTokens, 'globe',
        'CLAUDE.md + skill/agent/command descriptions loaded into every session, every project'),
      row(`Project (this repo)`, s.projectAlwaysChars, s.projectAlwaysTokens, 'repo',
        "This workspace's CLAUDE.md + skill/agent/command descriptions"),
      item('SessionStart hooks & MCP servers can add more at runtime — not measured', {
        icon: 'info',
        tooltip: 'Hooks that emit context and MCP tool schemas load at runtime and cannot be measured by a static scan',
      }),
    ];
  }
}

/** Context Weight: tier → entries, chars exact + ~token estimates. */
class WeighProvider extends BaseProvider {
  getChildren(element) {
    if (element) return element._children ?? [];
    const w = this.snapshot?.weigh;
    if (!w) return [];
    const row = (id, chars, tokens, icon) =>
      item(id, { description: `${fmt(chars)} chars · ~${fmt(tokens)} tok`, icon });
    const tiers = [];

    tiers.push(item(`Always loaded — ~${fmt(w.always.tokens)} tokens/session`, {
      icon: 'flame',
      tooltip: 'Injected into every session before your first prompt (this project)',
      children: w.always.entries.map((e) => row(e.label, e.chars, e.tokens, 'pulse')),
    }));
    if (w.global) {
      tiers.push(item(`Global — ~${fmt(w.global.always.tokens)} tokens/session (~/.claude)`, {
        icon: 'globe',
        tooltip: 'Loaded into every session in every project, from your ~/.claude config',
        children: w.global.always.entries.map((e) => row(e.label, e.chars, e.tokens, 'pulse')),
      }));
    }
    if (w.invoke.items.length) {
      tiers.push(item(`On invoke — ${w.invoke.items.length} items, ~${fmt(w.invoke.tokens)} tokens total`, {
        icon: 'play',
        tooltip: "The item's own .md body, loaded only when it is used",
        children: w.invoke.items.map((e) => row(e.id, e.chars, e.tokens, 'file')),
      }));
    }
    if (w.reference.items.length) {
      const bin = w.reference.binaryBytes ? ` (+${fmt(w.reference.binaryBytes)} B binary)` : '';
      tiers.push(item(`Referenced files — ~${fmt(w.reference.tokens)} tokens${bin}`, {
        icon: 'files',
        tooltip: 'references/, scripts/ etc. — read only if the item uses them',
        children: w.reference.items.map((e) =>
          row(`${e.id} (${e.files} files)`, e.chars, e.tokens, 'folder')),
      }));
    }
    if (w.other.items.length) {
      tiers.push(item(`Other ecosystems — ~${fmt(w.other.tokens)} tokens`, {
        icon: 'extensions',
        tooltip: 'Always loaded, but by their own tool (Cursor, Codex, Gemini, ...)',
        children: w.other.items.map((e) => row(`${e.id} [${e.kind}]`, e.chars, e.tokens, 'file')),
      }));
    }
    const notes = [];
    notes.push(item(w.notes.mcpFiles > 0
      ? `MCP: ${w.notes.mcpServers} server(s) — schemas load at runtime, not measurable offline`
      : 'MCP config: none found', { icon: 'plug' }));
    if (w.notes.settingsFiles > 0) notes.push(item('settings hooks run as shell — no context cost', { icon: 'terminal' }));
    for (const id of w.notes.missingDescriptions) {
      notes.push(item(`${id} has NO description — may never be selected`, { icon: 'warning', color: 'list.warningForeground' }));
    }
    tiers.push(item('Notes', { icon: 'info', children: notes }));
    return tiers;
  }
}

/** Manifest Check: the live +/-/~ diff against the committed manifest. */
class CheckProvider extends BaseProvider {
  getChildren(element) {
    if (element) return element._children ?? [];
    const c = this.snapshot?.check;
    if (!c) return [];
    if (!c.hasManifest) return []; // viewsWelcome content takes over
    if (c.code === 0 && !c.lines.some((l) => /^[+~-] /.test(l))) {
      return [item('No capability changes', { icon: 'pass', color: 'testing.iconPassed' })];
    }
    return c.lines
      .filter((l) => /^[+~-] /.test(l))
      .map((l) => {
        const kind = l[0];
        return item(l.slice(2), {
          icon: kind === '+' ? 'diff-added' : kind === '-' ? 'diff-removed' : 'diff-modified',
          color: kind === '+' ? 'testing.iconFailed' : kind === '-' ? 'testing.iconPassed' : 'list.warningForeground',
          tooltip: kind === '+'
            ? 'NEW capability — fails check until the manifest is regenerated and committed'
            : kind === '-' ? 'Removed capability (safe)' : 'Content changed, capabilities unchanged',
        });
      });
  }
}

module.exports = { SessionProvider, CapabilitiesProvider, WeighProvider, CheckProvider, fmt };
