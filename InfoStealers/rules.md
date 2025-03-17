# Rules for Info Stealers



### SPL/Sysmon - Suspicious File Access and Modifications

```
`indextime` `sysmon` EventID=11 TargetFilename IN ("*\\Chrome\\User Data\\Default\\Cookies", "*\\Edge\\User Data\\Default\\Cookies")
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="Python decryption routine detected",
    mitre_category="Defense_Evasion",
    mitre_technique="Deobfuscate/Decode Files or Information",
    mitre_technique_id="T1140",
    mitre_subtechnique="", 
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1140/",
    creator="Cpl Iverson",
    last_tested=""),
    upload_date="2025-03-10",
    last_modify_date="2025-03-10",
    mitre_version="v16",
    priority="High"
| `process_create_whitelist` 
| eval indextime = _indextime 
| convert ctime(indextime) 
| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority
| collect `jarvis_index`
```

### SPL/Sysmon - Suspicious Process Execution

```
`indextime` `sysmon` EventID=1 Image="*python.exe" CommandLine="*decrypt_value*"
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="Python decryption routine detected",
    mitre_category="Defense_Evasion",
    mitre_technique="Deobfuscate/Decode Files or Information",
    mitre_technique_id="T1140",
    mitre_subtechnique="", 
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1140/",
    creator="Cpl Iverson",
    last_tested=""),
    upload_date="2025-03-10",
    last_modify_date="2025-03-10",
    mitre_version="v16",
    priority="High"
| `process_create_whitelist` 
| eval indextime = _indextime 
| convert ctime(indextime) 
| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority
| collect `jarvis_index`
```

### Sigma - Decryption Detection

```
title: Suspicious Decryption Activity
description: Detects potential use of decryption routines (win32crypt, AES)
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    CommandLine|contains:
      - "CryptUnprotectData"
      - "AESGCM"
  condition: selection
```

### SPL/Sysmon - Browser History and Autofill Data Exfiltration
```
`sysmon` EventID=11 TargetFilename IN ("*\\Chrome\\User Data\\Default\\History", "*\\Edge\\User Data\\Default\\History")
```

### SPL/Sysmon - Encoded Powershell command [1]

```
`idnextime` `powershell` (process_name="powershell.exe" OR command_line="*powershell.exe*") AND (command_line="*-enc *" OR command_line="*-EncodedCommand *")
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="Encoded PowerShell command detected",
    mitre_category="Defense_Evasion",
    mitre_technique="Obfuscated Files or Information",
    mitre_technique_id="T1027",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1027/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-10",
    last_modify_date="2025-03-10"),
    mitre_version="v16",
    priority="High"
| `process_create_whitelist`
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority
| collect `jarvis_index`
```


```
`indextim` `powershell` (process_name="powershell.exe" OR command_line="*powershell.exe*")
    AND command_line="*-W Hidden*"
    AND command_line="*Invoke-WebRequest*"
    AND command_line="*/uploads/*"
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="Suspicious PowerShell web download with hidden window",
    mitre_category="Command and Control",
    mitre_technique="Ingress Tool Transfer",
    mitre_technique_id="T1105",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1105/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-16",
    last_modify_date="2025-03-16",
    mitre_version="v16",
    priority="High"
| `process_create_whitelist`
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority
| collect `jarvis_index`
```

```
`indextime` `sysmon` (process_name="mshta.exe" OR command_line="*mshta*") AND (command_line="*http://*" OR command_line="*https://*")
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="Suspicious mshta execution with remote URL detected",
    mitre_category="Execution",
    mitre_technique="Mshta",
    mitre_technique_id="T1218.005",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1218/005/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-16",
    last_modify_date="2025-03-16",
    mitre_version="v16",
    priority="High"
| `process_create_whitelist`
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority
| collect `jarvis_index`
```

ALL T1204.002 already added

https://attack.mitre.org/techniques/T1010/
```
`indextime` `powershell` EventCode="4103" 
| where CommandLine LIKE "%Get-Process%" AND CommandLine LIKE "%mainWindowTitle%"
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="PowerShell enumeration using Get-Process and mainWindowTitle",
    mitre_category="Discovery",
    mitre_technique="System Information Discovery",
    mitre_technique_id="T1082",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1082/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-16",
    last_modify_date="2025-03-16",
    mitre_version="v16",
    priority="Medium"
| eval indextime = _indextime 
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority
| collect `jarvis_index`

```

https://attack.mitre.org/techniques/T1010/
```
`indextime` (`sysmon` EventCode="1") OR (`windows-security` EventCode="4688")
| where CommandLine LIKE "%Get-Process%" AND CommandLine LIKE "%mainWindowTitle%"
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="Suspicious process enumeration using Get-Process and mainWindowTitle",
    mitre_category="Discovery",
    mitre_technique="System Information Discovery",
    mitre_technique_id="T1082",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1082/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-16",
    last_modify_date="2025-03-16",
    mitre_version="v16",
    priority="Medium"
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority
| collect `jarvis_index`
```

T1010 - Analytic 1 - Suspicious Commands
```
sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4103" 
| where CommandLine LIKE "%Get-Process%" AND CommandLine LIKE "%mainWindowTitle%"

```
T1010 - Analytic 1 - Suspicious Processes
```
(`sysmon` EventCode="1") OR (`windows-security` EventCode="4688") 
| where CommandLine LIKE "%Get-Process%" AND CommandLine LIKE "%mainWindowTitle%"
```




## References
[1]: https://www.group-ib.com/blog/clickfix-the-social-engineering-technique-hackers-use-to-manipulate-victims
[2]: https://0xmrmagnezi.github.io/malware%20analysis/LummaStealer/
