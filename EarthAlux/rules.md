
[T1010] Suspicious Process Enumeration via Get-Process and mainWindowTitle
```
`indextime` `sysmon` <SEARCHSTRING>
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1010 - Analytic 1 - Suspicious Process Enumeration",
    mitre_category="Discovery",
    mitre_technique="Application Window Discovery",
    mitre_technique_id="T1010",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1010/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-16",
    last_modify_date="2025-03-16",
    mitre_version="v16",
    priority="Medium",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```