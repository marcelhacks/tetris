from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

root=Path(sys.argv[1] if len(sys.argv)>1 else "downloaded")
out=Path(sys.argv[2] if len(sys.argv)>2 else "adjudication-smb")
out.mkdir(parents=True,exist_ok=True)
run_id=os.environ.get("GITHUB_RUN_ID","unknown")


def find_json(name):
    matches=list(root.rglob(name))
    if not matches: return None,None
    path=matches[0]
    try: return path,json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception: return path,None

attacker_path,attacker=find_json("attacker-smb-result.json")
victim_path,victim=find_json("victim-smb-result.json")
launcher_path,launcher=find_json("netonly-launcher.json")
attack_path,attack=find_json("http-attack-result.json")
attacker=attacker or {}; victim=victim or {}; launcher=launcher or {}; attack=attack or {}
proof=attacker.get("target_proof") or {}
principal=str(proof.get("principal") or "")
nonce=str(attacker.get("nonce") or victim.get("nonce") or run_id)
victim_conditions=victim.get("proof_conditions") or {}
proxy_events=victim.get("proxy_events") or []
procmon_events=((victim.get("procmon") or {}).get("firefox_path_events") or [])
conditions={
    "same_run_nonce":str(proof.get("nonce"))==nonce and nonce==str(run_id),
    "anonymous_request_rejected":(attacker.get("anonymous_control") or {}).get("status")==401,
    "anonymous_request_caused_no_action":not bool((attacker.get("anonymous_control") or {}).get("proof_exists")),
    "real_firefox":victim_conditions.get("real_firefox") is True,
    "native_folder_picker_completed":victim_conditions.get("native_picker_selected") is True,
    "reparse_link_created_after_picker":victim_conditions.get("link_created_after_picker") is True,
    "explicit_legacy_filesystem_call":victim_conditions.get("explicit_api_call") is True,
    "network_flow_started_during_firefox_call":victim_conditions.get("proxy_accepted_during_trigger") is True,
    "firefox_process_file_operation_attribution":victim_conditions.get("firefox_file_operation_attribution") is True,
    "netonly_lab_identity_launched":launcher.get("launched") is True and str(launcher.get("username","")).lower()=="lab\\victim",
    "relayed_ntlm_identity_is_lab_victim":bool(re.search(r"(?i)(^|[\\/@])victim($|[\\/@])|^victim$",principal)),
    "authenticated_relay_request_succeeded":int(attack.get("status") or 0)==200,
    "authenticated_integrity_write":proof.get("integrity_marker")==f"AUTHENTICATED_WRITE:{principal}:{nonce}",
    "authenticated_availability_delete":proof.get("availability_existed_before") is True and proof.get("availability_exists_after") is False,
    "authenticated_fixed_command_execution":proof.get("execution_marker")==f"AUTHENTICATED_COMMAND_EXEC_{nonce}" and int(proof.get("command_returncode",-1))==0,
}
confirmed=all(conditions.values())
verdict="CONFIRMED_FIREFOX_REPARSE_FORCED_NTLM_RELAY_TO_AUTHENTICATED_COMMAND_EXECUTION" if confirmed else "NOT_CONFIRMED"
report={
    "run_id":run_id,"verdict":verdict,
    "conditional_cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" if confirmed else None,
    "conditional_cvss_score":9.6 if confirmed else None,
    "conditions":conditions,"principal":principal,"nonce":nonce,
    "browser":victim.get("capabilities"),"firefox_parent_pid":victim.get("parent_pid"),
    "browser_call":victim.get("browser_call"),"reparse_link":victim.get("link"),
    "proxy_events":proxy_events,"procmon_firefox_events":procmon_events,
    "authenticated_target_proof":proof,"relay_plugin_result":attack,
    "anonymous_control":attacker.get("anonymous_control"),
    "source_paths":{"attacker":str(attacker_path) if attacker_path else None,
                    "victim":str(victim_path) if victim_path else None,
                    "launcher":str(launcher_path) if launcher_path else None,
                    "attack":str(attack_path) if attack_path else None},
}
(out/"adjudication.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
lines=["# Firefox selected-directory reparse to NTLM relay lab","",f"**Verdict:** `{verdict}`",""]
if confirmed:
    lines += [
        "The lab established a real Firefox native-picker to authenticated-command chain:","",
        "1. Firefox accepted a directory through the native folder picker.",
        "2. Only after the picker closed, the lab inserted a directory symbolic link beneath that root.",
        "3. Web content invoked `FileSystemDirectoryEntry.getFile()` through that link.",
        "4. Process Monitor attributed the local reparse-backed file operation to Firefox.",
        "5. The Windows SMB redirector emitted authentication for the disposable `LAB\\victim` network identity.",
        "6. A remote NTLM relay forwarded that authentication without knowing the password.",
        "7. The controlled target authenticated the relayed identity and performed a fixed write, deletion, and marker command.","",
        "Conditional environmental vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` = 9.6.","",
        "The Base vector assumes a relay-compatible Windows environment and a selected attacker-supplied tree containing the reparse point.",
    ]
else:
    lines += ["The strict gate failed. No 9.6 claim is made.","","## Failed conditions",""] + [f"- `{key}`" for key,value in conditions.items() if not value]
lines += ["","## All conditions",""] + [f"- `{key}`: `{value}`" for key,value in conditions.items()]
(out/"adjudication.md").write_text("\n".join(lines),encoding="utf-8")
if confirmed:
    (out/f"CONFIRMED_9_6_{run_id}.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
print(json.dumps({"verdict":verdict,"conditions":conditions},indent=2))
