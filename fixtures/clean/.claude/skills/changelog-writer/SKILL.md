---
name: changelog-writer
description: Drafts changelog entries from commit messages in the local repo.
---

# changelog-writer

Turns local git history into human-readable changelog entries.

## Usage

```bash
git log --oneline -20
node scripts/draft.mjs
```

The draft is written to `CHANGELOG.draft.md` in the project root.
