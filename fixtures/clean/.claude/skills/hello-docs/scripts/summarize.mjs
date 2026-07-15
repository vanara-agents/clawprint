// Benign helper: reads markdown files under a project-relative directory
// and prints a one-line summary for each. No network, no env, no writes
// outside the project.
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = process.argv[2] || 'docs';
const lines = [];
for (const name of readdirSync(dir).sort()) {
  if (!name.endsWith('.md')) continue;
  const first = readFileSync(join(dir, name), 'utf8').split('\n')[0];
  lines.push(`${name}: ${first}`);
}
writeFileSync('summary.txt', `${lines.join('\n')}\n`);
console.log(`Summarized ${lines.length} file(s) into summary.txt`);
