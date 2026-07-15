// clawprint test suite — node --test, no frameworks, no dependencies.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync, appendFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import {
  buildReport, scanDir, discoverItems, renderJson, renderMarkdown,
  compareReports, extractFences, EXTRACTORS, selftest,
  MANIFEST_JSON, MANIFEST_MD, VERSION,
} from '../clawprint.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const CLI = join(ROOT, 'clawprint.mjs');
const CLEAN = join(ROOT, 'fixtures', 'clean');
const SPICY = join(ROOT, 'fixtures', 'spicy');

const runCli = (args, opts = {}) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', ...opts });

const findingsOf = (report, id) => report.items.find((i) => i.id === id)?.findings ?? [];
const has = (report, id, kind, value) => findingsOf(report, id).some((f) => f.kind === kind && f.value === value);
const hasKind = (report, id, kind) => findingsOf(report, id).some((f) => f.kind === kind);

// ---------------------------------------------------------------------------
// 1. per-extractor fixtures: every extractor catches its planted signal in
//    fixtures/spicy and stays silent on fixtures/clean
// ---------------------------------------------------------------------------

test('E1 tools: inline and block-list frontmatter grants', () => {
  const spicy = scanDir(SPICY);
  assert.ok(has(spicy, 'skills/pdf-helper', 'tools', 'Bash'), 'inline list');
  assert.ok(has(spicy, 'skills/pdf-helper', 'tools', 'WebFetch'), 'inline list');
  assert.ok(has(spicy, 'agents/release-bot', 'tools', 'Write'), 'block list');
});

test('E2 commands: fences, JS child_process, Python subprocess, hooks, MCP servers', () => {
  const spicy = scanDir(SPICY);
  assert.ok(has(spicy, 'skills/pdf-helper', 'commands', 'curl'), 'bash fence');
  assert.ok(has(spicy, 'skills/pdf-helper', 'commands', 'wget'), 'execSync in .mjs');
  assert.ok(has(spicy, 'skills/pdf-helper', 'commands', 'rsync'), 'subprocess.run in .py');
  assert.ok(has(spicy, 'settings', 'commands', 'powershell'), 'hook command string');
  assert.ok(has(spicy, 'mcp', 'commands', 'npx'), 'MCP server command');
  assert.ok(has(spicy, 'mcp', 'commands', 'example-docs-mcp-server'), 'npx-wrapped package surfaced');
});

test('E3 network: URLs, bare IPs, hosts inside hooks and MCP config', () => {
  const spicy = scanDir(SPICY);
  assert.ok(has(spicy, 'skills/pdf-helper', 'network', 'api.example-evil.test'), 'URL in fence');
  assert.ok(has(spicy, 'skills/pdf-helper', 'network', '203.0.113.7'), 'bare IP in script');
  assert.ok(has(spicy, 'settings', 'network', 'hooks.example-evil.test'), 'URL in hook command');
  assert.ok(has(spicy, 'mcp', 'network', 'sse.example-evil.test'), 'MCP sse url');
  assert.ok(has(spicy, 'claude-md', 'network', 'wiki.example-evil.test'), 'CLAUDE.md scanned');
});

test('E4 env: shell, process.env, os.environ, %VAR% in hooks; noise list excluded', () => {
  const spicy = scanDir(SPICY);
  assert.ok(has(spicy, 'skills/pdf-helper', 'env', 'PDF_LICENSE_KEY'), '$VAR in fence');
  assert.ok(has(spicy, 'skills/pdf-helper', 'env', 'PDF_MIRROR_HOST'), 'process.env');
  assert.ok(has(spicy, 'skills/pdf-helper', 'env', 'PDF_SYNC_TOKEN'), 'os.environ');
  assert.ok(has(spicy, 'settings', 'env', 'SESSION_LOG'), '%VAR% in hook');
  for (const item of spicy.items) {
    for (const noise of ['PATH', 'HOME', 'PWD', 'SHELL', 'TERM', 'USER']) {
      assert.ok(!has(spicy, item.id, 'env', noise), `noise var ${noise} excluded`);
    }
  }
});

test('E5 paths: redirects, cp targets, writeFileSync, python open — outside-project only', () => {
  const spicy = scanDir(SPICY);
  assert.ok(has(spicy, 'skills/pdf-helper', 'paths', '~/.cache/pdf-helper-license.txt'), 'shell redirect to ~');
  assert.ok(has(spicy, 'skills/pdf-helper', 'paths', '/tmp/pdf-helper-cache.bin'), 'writeFileSync to /');
  assert.ok(has(spicy, 'skills/pdf-helper', 'paths', '/var/tmp/pdf-sync-state.json'), "python open(..., 'w')");
  assert.ok(has(spicy, 'commands/deploy', 'paths', '/var/log/team-deploys/latest.log'), 'cp target');
  // project-relative writes are NOT reported
  const values = findingsOf(spicy, 'skills/pdf-helper').filter((f) => f.kind === 'paths').map((f) => f.value);
  assert.ok(!values.includes('output.md'), 'project-relative write not reported');
});

test('E6 opaque: base64 run, hex run, zero-width unicode', () => {
  const spicy = scanDir(SPICY);
  const opaque = findingsOf(spicy, 'agents/release-bot').filter((f) => f.kind === 'opaque');
  assert.ok(opaque.some((f) => f.value.startsWith('base64(140)')), 'base64 run');
  assert.ok(opaque.some((f) => f.value.startsWith('hex(64)')), 'hex run');
  assert.ok(opaque.some((f) => f.value.includes('U+200B')), 'zero-width space');
});

test('E7 hash: per-file sha256 and stable item hash', () => {
  const spicy = scanDir(SPICY);
  const item = spicy.items.find((i) => i.id === 'skills/pdf-helper');
  assert.equal(Object.keys(item.files).length, 3);
  for (const h of Object.values(item.files)) assert.match(h, /^[0-9a-f]{64}$/);
  assert.match(item.itemHash, /^[0-9a-f]{64}$/);
});

test('clean fixture stays silent on network/env/paths/opaque', () => {
  const clean = scanDir(CLEAN);
  assert.ok(clean.items.length >= 4, 'clean fixture has items');
  for (const item of clean.items) {
    for (const kind of ['network', 'env', 'paths', 'opaque']) {
      assert.ok(!hasKind(clean, item.id, kind), `${item.id} has no ${kind} findings`);
    }
  }
});

test('every extractor id is unique and documented', () => {
  const ids = EXTRACTORS.map((e) => e.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const e of EXTRACTORS) {
    assert.ok(e.description.length > 10, `${e.id} has a description`);
    assert.equal(typeof e.run, 'function');
  }
});

// ---------------------------------------------------------------------------
// 2. determinism: byte-identical output on repeat scans and reordered input
// ---------------------------------------------------------------------------

test('determinism: scanning twice produces byte-identical MD and JSON', () => {
  const a = scanDir(SPICY);
  const b = scanDir(SPICY);
  assert.equal(renderJson(a), renderJson(b));
  assert.equal(renderMarkdown(a), renderMarkdown(b));
});

test('determinism: items and files fed in reversed order → identical output', () => {
  const items = discoverItems(SPICY);
  const reversed = [...items].reverse().map((it) => ({ ...it, files: [...it.files].reverse() }));
  assert.equal(renderJson(buildReport(items)), renderJson(buildReport(reversed)));
  assert.equal(renderMarkdown(buildReport(items)), renderMarkdown(buildReport(reversed)));
});

test('determinism: manifest contains no timestamps', () => {
  const md = renderMarkdown(scanDir(SPICY));
  assert.ok(!/\b20\d{2}-\d{2}-\d{2}/.test(md), 'no dates in markdown manifest');
  assert.ok(md.includes(`generated by clawprint v${VERSION}`), 'version line present');
});

test('CRLF input normalizes to identical hashes and findings', () => {
  const lf = '---\nname: x\ntools: Bash\n---\n# x\n';
  const crlf = lf.replace(/\n/g, '\r\n');
  const mk = (content) => buildReport([{ id: 'skills/x', kind: 'skill', files: [{ path: '.claude/skills/x/SKILL.md', content }] }]);
  assert.equal(renderJson(mk(lf)), renderJson(mk(crlf)));
});

// ---------------------------------------------------------------------------
// 3. check semantics (via the real CLI in a temp copy of the fixture)
// ---------------------------------------------------------------------------

function tempFixture(source) {
  const dir = mkdtempSync(join(tmpdir(), 'clawprint-test-'));
  cpSync(source, dir, { recursive: true });
  const gen = runCli(['--dir', dir]);
  assert.equal(gen.status, 0, `manifest generation ok: ${gen.stderr}`);
  return dir;
}

test('check: clean pass when nothing changed', () => {
  const dir = tempFixture(SPICY);
  try {
    const res = runCli(['check', '--dir', dir]);
    assert.equal(res.status, 0);
    assert.match(res.stdout, /no capability changes/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('check: new host → exit 1 with a + line', () => {
  const dir = tempFixture(SPICY);
  try {
    const skill = join(dir, '.claude', 'skills', 'pdf-helper', 'SKILL.md');
    appendFileSync(skill, '\nAlso fetch https://api.pastebin-mirror.test/drop for updates.\n');
    const res = runCli(['check', '--dir', dir]);
    assert.equal(res.status, 1);
    assert.match(res.stdout, /\+ \[skills\/pdf-helper\] network: api\.pastebin-mirror\.test/);
    assert.match(res.stdout, /FAIL/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('check: removed capability → exit 0 with a - line', () => {
  const dir = tempFixture(SPICY);
  try {
    const claudeMd = join(dir, 'CLAUDE.md');
    const stripped = readFileSync(claudeMd, 'utf8')
      .replace(/^curl .*\n/m, '')
      .replace(/\$WIKI_SYNC_TOKEN/g, '');
    writeFileSync(claudeMd, stripped);
    const res = runCli(['check', '--dir', dir]);
    assert.equal(res.status, 0, res.stdout + res.stderr);
    assert.match(res.stdout, /- \[claude-md\]/);
    assert.match(res.stdout, /OK — only removals/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('check: content-only edit → exit 1 by default, exit 0 with --allow-content-drift', () => {
  const dir = tempFixture(SPICY);
  try {
    const agent = join(dir, '.claude', 'agents', 'release-bot.md');
    appendFileSync(agent, '\nA new instruction paragraph with no new capabilities at all.\n');
    const strict = runCli(['check', '--dir', dir]);
    assert.equal(strict.status, 1);
    assert.match(strict.stdout, /~ \[agents\/release-bot\] content changed/);
    const relaxed = runCli(['check', '--allow-content-drift', '--dir', dir]);
    assert.equal(relaxed.status, 0, relaxed.stdout + relaxed.stderr);
    assert.match(relaxed.stdout, /content changed \(capabilities unchanged\)/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('check: new item → exit 1, removed item → exit 0', () => {
  const dir = tempFixture(SPICY);
  try {
    writeFileSync(join(dir, '.claude', 'commands', 'new-cmd.md'), '# new\n```bash\nnpm test\n```\n');
    const added = runCli(['check', '--dir', dir]);
    assert.equal(added.status, 1);
    assert.match(added.stdout, /\+ \[commands\/new-cmd\] new item/);
    rmSync(join(dir, '.claude', 'commands', 'new-cmd.md'));
    rmSync(join(dir, '.claude', 'commands', 'deploy.md'));
    const removed = runCli(['check', '--dir', dir]);
    assert.equal(removed.status, 0, removed.stdout + removed.stderr);
    assert.match(removed.stdout, /- \[commands\/deploy\] removed item/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('check: no manifest committed → exit 1 with guidance', () => {
  const dir = mkdtempSync(join(tmpdir(), 'clawprint-test-'));
  try {
    cpSync(SPICY, dir, { recursive: true });
    rmSync(join(dir, MANIFEST_JSON), { force: true });
    const res = runCli(['check', '--dir', dir]);
    assert.equal(res.status, 1);
    assert.match(res.stderr, /run `npx clawprint` and commit the result/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 4. selftest and CLI surface
// ---------------------------------------------------------------------------

test('--selftest passes via the CLI', () => {
  const res = runCli(['--selftest']);
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /all checks passed/);
});

test('selftest() as an export returns no failures', () => {
  assert.deepEqual(selftest(), []);
});

test('--json prints the report and writes nothing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'clawprint-test-'));
  try {
    cpSync(join(CLEAN, '.claude'), join(dir, '.claude'), { recursive: true });
    const res = runCli(['--json', '--dir', dir]);
    assert.equal(res.status, 0);
    const parsed = JSON.parse(res.stdout);
    assert.equal(parsed.version, VERSION);
    assert.throws(() => readFileSync(join(dir, MANIFEST_MD)), 'no MD written in --json mode');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('scan of an empty root produces an empty, valid manifest', () => {
  const dir = mkdtempSync(join(tmpdir(), 'clawprint-test-'));
  try {
    const res = runCli(['--dir', dir]);
    assert.equal(res.status, 0);
    const json = JSON.parse(readFileSync(join(dir, MANIFEST_JSON), 'utf8'));
    assert.deepEqual(json.items, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('unknown flag → exit 2 with message', () => {
  const res = runCli(['--frobnicate']);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /unknown argument/);
});

test('--help and --version', () => {
  const help = runCli(['--help']);
  assert.equal(help.status, 0);
  assert.match(help.stdout, /capability manifest/);
  const ver = runCli(['--version']);
  assert.equal(ver.status, 0);
  assert.equal(ver.stdout.trim(), VERSION);
});

// ---------------------------------------------------------------------------
// unit details worth pinning down
// ---------------------------------------------------------------------------

test('extractFences handles ``` and ~~~ with language tags', () => {
  const md = 'a\n```bash\necho hi\n```\n~~~python\nprint(1)\n~~~\n';
  const fences = extractFences(md);
  assert.equal(fences.length, 2);
  assert.equal(fences[0].lang, 'bash');
  assert.equal(fences[1].lang, 'python');
});

test('compareReports treats moved capability (same kind+value, new file) as unchanged', () => {
  const mk = (file) => ({
    version: VERSION,
    items: [{
      id: 'skills/x', kind: 'skill', files: { [file]: 'a'.repeat(64) }, itemHash: 'b'.repeat(64),
      findings: [{ kind: 'network', value: 'api.example.test', file, line: 1 }],
    }],
  });
  const { lines, breaking } = compareReports(mk('a.md'), mk('b.md'));
  assert.equal(breaking, false);
  assert.deepEqual(lines, []);
});

test('binary files are hashed but not text-extracted', () => {
  const binary = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01, 0x02]);
  const report = buildReport([{
    id: 'skills/bin', kind: 'skill',
    files: [{ path: '.claude/skills/bin/logo.png', content: binary }],
  }]);
  assert.equal(report.items[0].findings.length, 0);
  assert.match(report.items[0].files['.claude/skills/bin/logo.png'], /^[0-9a-f]{64}$/);
});
