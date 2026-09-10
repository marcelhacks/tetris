from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

root = Path(sys.argv[1] if len(sys.argv) > 1 else "downloaded-artifacts")
out = Path(sys.argv[2] if len(sys.argv) > 2 else "adjudication")
out.mkdir(parents=True, exist_ok=True)
run_id = os.environ.get("GITHUB_RUN_ID", "unknown")


def read_first(name: str):
    paths = list(root.rglob(name))
    if not paths:
        return None, None
    path = paths[0]
    try:
        return path, json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return path, None

attacker_path, attacker = read_first("attacker-result.json")
victim_path, victim = read_first("victim-result.json")
launcher_path, launcher = read_first("netonly-launcher.json")
attacker = attacker or {}
victim = victim or {}
launcher = launcher or {}
proof = attacker.get("target_proof") or {}
http_attack = attacker.get("http-attack-result") or attacker.get("http-attack-result".replace("-", "_")) or {}
if not http_attack:
    _, http_attack = read_first("http-attack-result.json")
    http_attack = http_attack or {}

principal = str(proof.get("principal") or "")
execution = str(proof.get("execution_marker") or "")
integrity = str(proof.get("integrity_marker") or "")
nonce = str(attacker.get("nonce") or victim.get("nonce") or run_id)
links = (victim.get("webdav_links") or []) + ([victim.get("smb_link")] if victim.get("smb_link") else [])
attempts = victim.get("attempts") or []
procmon_events = ((victim.get("procmon") or {}).get("firefox_path_events") or [])
proxy_events = victim.get("smb_proxy_final") or []

conditions = {
    "same_run_nonce": str(proof.get("nonce")) == nonce and nonce == str(run_id),
    "anonymous_control_rejected": (attacker.get("anonymous_control") or {}).get("status") == 401,
    "anonymous_control_no_action": not bool((attacker.get("anonymous_control") or {}).get("proof_exists")),
    "ntlm_principal_is_lab_victim": bool(re.search(r"(?i)(^|[\\/@])victim($|[\\/@])|^victim$", principal)),
    "relay_attack_received_success": int(http_attack.get("status") or 0) == 200,
    "authenticated_integrity_write": integrity == f"AUTHENTICATED_WRITE:{principal}:{nonce}",
    "authenticated_availability_delete": proof.get("availability_existed_before") is True and proof.get("availability_exists_after") is False,
    "authenticated_command_execution": execution == f"AUTHENTICATED_COMMAND_EXEC_{nonce}" and int(proof.get("command_returncode", -1)) == 0,
    "firefox_real_browser_started": str((victim.get("capabilities") or {}).get("browserName", "")).lower() == "firefox" and bool((victim.get("capabilities") or {}).get("browserVersion")),
    "native_folder_picker_completed": (victim.get("picker") or {}).get("page_phase") == "selected",
    "reparse_link_created": any(link and int(link.get("returncode", 1)) == 0 and link.get("lexists") for link in links),
    "firefox_api_triggered": bool(attempts),
    "firefox_process_attribution": bool(procmon_events) or (bool(attempts) and bool(victim.get("parent_pid"))),
    "netonly_process_launched": launcher.get("launched") is True and str(launcher.get("username", "")).lower().endswith("\\victim"),
}

confirmed = all(conditions.values())
verdict = "CONFIRMED_FIREFOX_REPARSE_NTLM_RELAY_AUTHENTICATED_COMMAND_EXECUTION" if confirmed else "NOT_CONFIRMED"
vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" if confirmed else None
report = {
    "run_id": run_id,
    "verdict": verdict,
    "cvss_vector_if_environment_is_relay_compatible": vector,
    "cvss_base_score_if_environment_is_relay_compatible": 9.6 if confirmed else None,
    "conditions": conditions,
    "principal": principal,
    "browser": victim.get("capabilities"),
    "firefox_parent_pid": victim.get("parent_pid"),
    "trigger_attempts": attempts,
    "procmon_firefox_events": procmon_events,
    "smb_proxy_events": proxy_events,
    "proof": proof,
    "http_attack": http_attack,
    "source_files": {
        "attacker": str(attacker_path) if attacker_path else None,
        "victim": str(victim_path) if victim_path else None,
        "launcher": str(launcher_path) if launcher_path else None,
    },
}
(out / "adjudication.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

lines = [
    "# Firefox reparse forced-authentication relay lab",
    "",
    f"**Verdict:** `{verdict}`",
    "",
]
if confirmed:
    lines += [
        "The controlled lab established the complete chain:",
        "",
        "1. a real Firefox process accepted a directory through its native picker;",
        "2. the selected directory was modified to contain a reparse link to the controlled network endpoint;",
        "3. Firefox's legacy directory API accessed that local-looking path;",
        "4. Windows emitted NTLM authentication for the lab-only network identity;",
        "5. the authentication was relayed without knowledge of the password;",
        "6. the receiving service authenticated the relayed identity;",
        "7. that identity performed an authenticated write, deletion, and fixed marker command.",
        "",
        f"Conditional CVSS vector: `{vector}` (9.6).",
        "",
        "The vector is valid only for environments in which automatic NTLM authentication and a relay-compatible service are present.",
    ]
else:
    lines += [
        "The strict proof gate did not pass. No 9.6 claim is made.",
        "",
        "## Failed conditions",
        "",
    ] + [f"- `{key}`" for key, value in conditions.items() if not value]
lines += ["", "## Proof conditions", ""] + [f"- `{key}`: `{value}`" for key, value in conditions.items()]
(out / "adjudication.md").write_text("\n".join(lines), encoding="utf-8")

if confirmed:
    confirmed_path = out / f"CONFIRMED_9_6_{run_id}.json"
    confirmed_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

print(json.dumps({"verdict": verdict, "conditions": conditions}, indent=2))
raise SystemExit(0)
