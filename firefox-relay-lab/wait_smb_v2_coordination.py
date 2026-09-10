from __future__ import annotations
import json, os, sys, time
from pathlib import Path
import requests
repo=os.environ['GITHUB_REPOSITORY']; branch=os.environ.get('LAB_BRANCH','runner-probe-20260910'); run_id=os.environ['GITHUB_RUN_ID']; output=Path(sys.argv[1])
url=f'https://raw.githubusercontent.com/{repo}/{branch}/.relay-coordination/{run_id}/smb-v2-attacker.json'
last={}
for _ in range(700):
    try:
        r=requests.get(url,headers={'User-Agent':'firefox-smb-relay-v2'},params={'cache':str(time.time_ns())},timeout=20)
        last={'status':r.status_code,'body':r.text[:1000]}
        if r.ok:
            data=r.json()
            if str(data.get('run_id'))==str(run_id) and data.get('smb'):
                output.write_text(json.dumps(data,indent=2),encoding='utf-8'); print(json.dumps(data,indent=2)); raise SystemExit(0)
    except Exception as exc: last={'error':repr(exc)}
    time.sleep(2)
Path(str(output)+'.error.json').write_text(json.dumps(last,indent=2),encoding='utf-8')
raise SystemExit('resilient SMB coordination unavailable')
