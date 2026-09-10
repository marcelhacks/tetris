from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import requests

repo = os.environ["GITHUB_REPOSITORY"]
branch = os.environ.get("LAB_BRANCH", "runner-probe-20260910")
run_id = os.environ["GITHUB_RUN_ID"]
output = Path(sys.argv[1])
url = f"https://raw.githubusercontent.com/{repo}/{branch}/.relay-coordination/{run_id}/attacker.json"
headers = {"User-Agent": "firefox-controlled-relay-lab"}
last = None
for attempt in range(600):
    try:
        response = requests.get(url, headers=headers,
                                params={"cache": str(time.time_ns())}, timeout=20)
        last = {"status": response.status_code, "body": response.text[:1000]}
        if response.ok:
            data = response.json()
            if str(data.get("run_id")) == str(run_id) and data.get("http") and data.get("smb"):
                output.write_text(json.dumps(data, indent=2), encoding="utf-8")
                print(json.dumps(data, indent=2))
                raise SystemExit(0)
    except Exception as exc:
        last = {"error": repr(exc)}
    time.sleep(2)
Path(str(output) + ".error.json").write_text(json.dumps(last, indent=2), encoding="utf-8")
raise SystemExit("attacker coordination was not published")
