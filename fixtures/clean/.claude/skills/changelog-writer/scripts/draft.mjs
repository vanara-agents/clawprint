// Benign helper: drafts a changelog from git history already fetched by
// the skill instructions. Writes only inside the project.
import { readFileSync, writeFileSync } from 'node:fs';

const log = readFileSync('git-log.txt', 'utf8');
const entries = log.split('\n').filter(Boolean).map((l) => `- ${l.replace(/^\w+\s+/, '')}`);
writeFileSync('CHANGELOG.draft.md', `# Draft changelog\n\n${entries.join('\n')}\n`);
console.log(`Drafted ${entries.length} entries.`);
