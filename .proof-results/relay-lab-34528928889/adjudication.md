# Firefox reparse forced-authentication relay lab

**Verdict:** `NOT_CONFIRMED`

The strict proof gate did not pass. No 9.6 claim is made.

## Failed conditions

- `same_run_nonce`
- `anonymous_control_rejected`
- `ntlm_principal_is_lab_victim`
- `relay_attack_received_success`
- `authenticated_integrity_write`
- `authenticated_availability_delete`
- `authenticated_command_execution`
- `firefox_real_browser_started`
- `native_folder_picker_completed`
- `reparse_link_created`
- `firefox_api_triggered`
- `firefox_process_attribution`
- `netonly_process_launched`

## Proof conditions

- `same_run_nonce`: `False`
- `anonymous_control_rejected`: `False`
- `anonymous_control_no_action`: `True`
- `ntlm_principal_is_lab_victim`: `False`
- `relay_attack_received_success`: `False`
- `authenticated_integrity_write`: `False`
- `authenticated_availability_delete`: `False`
- `authenticated_command_execution`: `False`
- `firefox_real_browser_started`: `False`
- `native_folder_picker_completed`: `False`
- `reparse_link_created`: `False`
- `firefox_api_triggered`: `False`
- `firefox_process_attribution`: `False`
- `netonly_process_launched`: `False`