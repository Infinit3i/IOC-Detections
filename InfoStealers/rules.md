# Rules for Info Stealers



- [x] - [T1140] Suspicious File Access and Modifications
```
`indextime` `sysmon` EventID=11 TargetFilename IN ("*\\Chrome\\User Data\\Default\\Cookies", "*\\Edge\\User Data\\Default\\Cookies", "*\\Chrome\\User Data\\Default\\History", "*\\Edge\\User Data\\Default\\History")
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

- [x] - [T1140] Suspicious Process Execution
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

- [x] - [T1027] Encoded Powershell command [1]
```
`indextime` `powershell` (process_name="powershell.exe" OR command_line="*powershell.exe*") AND (command_line="*-enc *" OR command_line="*-EncodedCommand *")
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - Encoded PowerShell command detected",
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

- [x] - [T1105] Hidden Powershell
```
`indextime` `powershell` (process_name="powershell.exe" OR command_line="*powershell.exe*") AND (command_line="*-W Hidden*" AND command_line="*Invoke-WebRequest*" AND command_line="*/uploads/*")
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - Suspicious PowerShell web download with hidden window",
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

- [x] - [T1218.005] INFOSTEALER - Suspicious mshta execution with remote URL detected
```
`indextime` `sysmon` (process_name="mshta.exe" OR command_line="*mshta*") AND (command_line="*http://*" OR command_line="*https://*")
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - Suspicious mshta execution with remote URL detected",
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

- [x] - [T1082] INFOSTEALER - PowerShell enumeration using Get-Process and mainWindowTitle
```
`indextime` `powershell` EventCode="4103" 
| where CommandLine LIKE "%Get-Process%" AND CommandLine LIKE "%mainWindowTitle%"
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - PowerShell enumeration using Get-Process and mainWindowTitle",
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

- [x] - [T1010] Suspicious Process Enumeration via Get-Process and mainWindowTitle
```
`indextime` (`sysmon` EventCode=1) OR (`windows` EventCode=4688) OR (`powershell` EventCode=4103)
| where CommandLine LIKE "%Get-Process%" AND CommandLine LIKE "%mainWindowTitle%"
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

- [x] - [T1570] Suspicious Named Pipe Creation (C2 / Browser Exfil)
```
`indextime` `sysmon` EventCode=17
| where match(Pipe, ".*\\\\pipe\\\\(msse-|postex|srvsvc).*") OR Pipe="*Chrome*" OR Pipe="*Edge*" OR Pipe="*sqlite*"
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1570 - Suspicious Named Pipe Activity (C2 / Browser Exfil)",
    mitre_category="Lateral Movement",
    mitre_technique="Lateral Tool Transfer",
    mitre_technique_id="T1570",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1570/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-20",
    last_modify_date="2025-03-20",
    mitre_version="v16",
    priority="Medium",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name Pipe Image ProcessId ProcessGuid original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

- [x] - [I1012] Spike in Registry Access (Potential Pre-Reverse Shell Activity)
```
`indextime` `sysmon` EventCode=13
| timechart span=1m count by Image
| eventstats avg(count) as avg_count, stdev(count) as stddev_count
| eval threshold=(avg_count + (2 * stddev_count))
| where count > threshold
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1012 - Registry Spike (Anomaly)",
    mitre_category="Discovery",
    mitre_technique="Query Registry",
    mitre_technique_id="T1012",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1012/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-20",
    last_modify_date="2025-03-20",
    mitre_version="v16",
    priority="Medium",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime count threshold Image mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`

```

- [x] - [I1012] High Volume Registry Access (TargetObject Enumeration)
```
`indextime` `sysmon` EventCode=13
| stats count by _time, TargetObject
| where count > 5
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1012 - High Volume Registry Enumeration",
    mitre_category="Discovery",
    mitre_technique="Query Registry",
    mitre_technique_id="T1012",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1012/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-20",
    last_modify_date="2025-03-20",
    mitre_version="v16",
    priority="Medium",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name TargetObject count mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

- [x] - [T1059] Python Script Execution Logging to “results” File (Suspicious Scripting Activity)
```
`indextime` `sysmon` EventCode=1
| search Image="*python*.exe" CommandLine="*results*"
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1059 - Analytic 1 - Suspicious Script Execution",
    mitre_category="Execution",
    mitre_technique="Command and Scripting Interpreter",
    mitre_technique_id="T1059",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1059/",
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

- [x] - [T1012] Registry Modification Spike Indicative of Enumeration or Pre-Execution Behavior
```
`indextime` `sysmon` EventCode=13
| stats count by _time, TargetObject
| where count > 5
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1012 - Analytic 1 - Suspicious Registry Queries",
    mitre_category="Discovery",
    mitre_technique="Query Registry",
    mitre_technique_id="T1012",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1012/",
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


- [x] - [T1555.003] Unauthorized Access to Browser Credential Stores (SQLite: Cookies, History, Web Data)
```
`indextime` `sysmon` EventCode=10
| search TargetFilename="*Cookies" OR TargetFilename="*History" OR TargetFilename="*Web Data"
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1555.003 - Analytic 1 - Unauthorized Browser Data Access",
    mitre_category="Credential Access",
    mitre_technique="Credentials from Password Stores",
    mitre_technique_id="T1555",
    mitre_subtechnique="Web Browsers",
    mitre_subtechnique_id="T1555.003",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1555/003/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-20",
    last_modify_date="2025-03-20",
    mitre_version="v16",
    priority="High",
    custom_category="infostealer",
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority
| collect `jarvis_index`
```

- [x] - [T1041] High-Volume HTTP/S Exfiltration Attempt via Suspicious Process
```
`indextime` `sysmon` EventCode=3
| search DestinationPort=80 OR DestinationPort=443
| stats count by DestinationIp Image
| where count > 5
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1041 - Analytic 1 - Suspicious Data Exfiltration",
    mitre_category="Exfiltration",
    mitre_technique="Exfiltration Over C2 Channel",
    mitre_technique_id="T1041",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1041/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-20",
    last_modify_date="2025-03-20",
    mitre_version="v16",
    priority="High",
    custom_category="infostealer",
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```


- [x] - [T1059.006] Detect Execution of Python Infostealer
```
`indextime` `windows` EventCode=4688
| search NewProcessName="*python.exe" CommandLine="*results*"
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1059.006 - Suspicious Python Execution",
    mitre_category="Execution",
    mitre_technique="Command and Scripting Interpreter",
    mitre_technique_id="T1059",
    mitre_subtechnique="Python",
    mitre_subtechnique_id="T1059.006",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1059/006/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-20",
    last_modify_date="2025-03-20",
    mitre_version="v16",
    priority="High",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name NewProcessName ProcessId ParentProcessName ParentProcessId CommandLine mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

- [x] - [T1555.003] Detect Access to Browser Credential Storage
```
`indextime` `windows` EventCode=4663
| search ObjectName="*Cookies" OR ObjectName="*Login Data" OR ObjectName="*Web Data" OR ObjectName="*History"
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1555.003 - Unauthorized Browser Credential Access",
    mitre_category="Credential Access",
    mitre_technique="Credentials from Password Stores",
    mitre_technique_id="T1555",
    mitre_subtechnique="Web Browsers",
    mitre_subtechnique_id="T1555.003",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1555/003/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-20",
    last_modify_date="2025-03-20",
    mitre_version="v16",
    priority="High",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name ObjectName ProcessName ProcessId Accesses mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

- [x] - [T1012] Detect Registry Modification for Browser Decryption Key
```
indextime 
index=wineventlog EventCode=4657
| search ObjectName="*os_crypt*"
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1012 - Suspicious Registry Query (Master Key Extraction)",
    mitre_category="Discovery",
    mitre_technique="Query Registry",
    mitre_technique_id="T1012",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1012/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-20",
    last_modify_date="2025-03-20",
    mitre_version="v16",
    priority="Medium",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name ObjectName ProcessName ProcessId mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

- [x] - [T1036.003] Detection: File Renamed or Created as .py (Suspicious Python Script Drop)
```
`indextime` (`windows` EventCode=4663 ObjectName="*.py") OR (`sysmon` EventCode=11 TargetFilename="*.py")
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1036.003 - File Renamed or Created as Python Script",
    mitre_category="Defense Evasion",
    mitre_technique="Masquerading",
    mitre_technique_id="T1036",
    mitre_subtechnique="Rename System Utilities",
    mitre_subtechnique_id="T1036.003",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1036/003/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-20",
    last_modify_date="2025-03-20",
    mitre_version="v16",
    priority="Medium",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name ObjectName TargetFilename ProcessName Image ProcessId mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

- [x] - [T1059] Python Script Execution (Suspicious Results File Usage)
```
`indextime` (`windows` EventCode=4688 NewProcessName="*python.exe" CommandLine="*results*") OR (`sysmon` EventCode=1 Image="*python.exe" CommandLine="*results*")
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1059.006 - Suspicious Python Script Execution",
    mitre_category="Execution",
    mitre_technique="Command and Scripting Interpreter",
    mitre_technique_id="T1059",
    mitre_subtechnique="Python",
    mitre_subtechnique_id="T1059.006",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1059/006/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-20",
    last_modify_date="2025-03-20",
    mitre_version="v16",
    priority="High",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name NewProcessName Image ProcessId CommandLine ParentProcessName ParentProcessId mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

- [x] - [T1555] Browser Credential File Access
```
`indextime` (`windows` EventCode=4663 ObjectName="*Cookies" OR ObjectName="*Login Data" OR ObjectName="*Web Data" OR ObjectName="*History") OR (`sysmon` EventCode=10 TargetFilename="*Cookies" OR TargetFilename="*Login Data" OR TargetFilename="*Web Data" OR TargetFilename="*History")
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1555.003 - Browser Credential File Access",
    mitre_category="Credential Access",
    mitre_technique="Credentials from Password Stores",
    mitre_technique_id="T1555",
    mitre_subtechnique="Web Browsers",
    mitre_subtechnique_id="T1555.003",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1555/003/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-20",
    last_modify_date="2025-03-20",
    mitre_version="v16",
    priority="High",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name ObjectName TargetFilename ProcessName Image ProcessId Accesses mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

- [x] - [T1012] Registry Key Access (Browser Master Key)
```
`indextime` (`windows` EventCode=4657 ObjectName="*os_crypt*") OR (`sysmon` EventCode=13 TargetObject="*os_crypt*")
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1012 - Suspicious Registry Key Query",
    mitre_category="Discovery",
    mitre_technique="Query Registry",
    mitre_technique_id="T1012",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1012/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-20",
    last_modify_date="2025-03-20",
    mitre_version="v16",
    priority="Medium",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name ObjectName TargetObject ProcessName Image ProcessId mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

- [x] - [T1041] Exfiltration over Network (HTTP/HTTPS burst)
```
`indextime` (`windows` EventCode=5156 DestinationPort=80 OR DestinationPort=443) OR (`sysmon` EventCode=3 DestinationPort=80 OR DestinationPort=443)
| stats count by DestinationIp ApplicationName Image
| where count > 5
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1041 - High-Volume C2 Exfiltration",
    mitre_category="Exfiltration",
    mitre_technique="Exfiltration Over C2 Channel",
    mitre_technique_id="T1041",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1041/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-20",
    last_modify_date="2025-03-20",
    mitre_version="v16",
    priority="High",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name ApplicationName Image DestinationIp DestinationPort mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

[T1110.001] Reading Credentials
```
`indextime` (`windows-security` EventCode=5379)
| bin _time span=1m
| stats count by _time, host, user
| where count > 30
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1110.001 - Excessive Credential Validation (DPAPI Access)",
    mitre_category="Credential Access",
    mitre_technique="Brute Force",
    mitre_technique_id="T1110",
    mitre_subtechnique="Password Guessing",
    mitre_subtechnique_id="T1110.001",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1110/001/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-24",
    last_modify_date="2025-03-24",
    mitre_version="v16",
    priority="Medium",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host user mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

[T1059.006] INFOSTEALER - Python Launcher Execution
```
`indextime` (`sysmon` Image="*\\Python\\Launcher\\py.exe")
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1059.006 - Python Launcher Execution",
    mitre_category="Execution",
    mitre_technique="Command and Scripting Interpreter",
    mitre_technique_id="T1059",
    mitre_subtechnique="Python",
    mitre_subtechnique_id="T1059.006",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1059/006/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-24",
    last_modify_date="2025-03-24",
    mitre_version="v16",
    priority="Medium",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| eval event_description="Execution of Python Launcher (py.exe) via Sysmon Image field"
| table _time indextime event_description hash_sha256 host user Image CommandLine ParentImage ParentCommandLine mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```


```
`indextime` (`sysmon` Message="*Network connection detected*" AND "DestinationPort: 3389")
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1021.001 - Suspicious RDP (Port 3389) Network Connection",
    mitre_category="Lateral Movement",
    mitre_technique="Remote Services",
    mitre_technique_id="T1021",
    mitre_subtechnique="Remote Desktop Protocol",
    mitre_subtechnique_id="T1021.001",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1021/001/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-24",
    last_modify_date="2025-03-24",
    mitre_version="v16",
    priority="High",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| eval event_description="RDP (Port 3389) network connection detected via Sysmon message field"
| table _time indextime event_description hash_sha256 host user SourceIp DestinationIp DestinationPort Image CommandLine mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```


[T1110.001] INFOSTEALER - Multiple Failed Logons Followed by Success
```
`indextime` (`windows-security` (EventCode=4625 OR EventCode=4624))
| eval status=case(EventCode=4625, "fail", EventCode=4624, "success")
| stats count(eval(status="fail")) as fail_count,
        values(eval(if(status="success", _time, null()))) as success_time
    by user host
| where fail_count > 5 AND isnotnull(success_time)
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1110.001 - Multiple Failed Logons Followed by Success",
    mitre_category="Credential Access",
    mitre_technique="Brute Force",
    mitre_technique_id="T1110",
    mitre_subtechnique="Password Guessing",
    mitre_subtechnique_id="T1110.001",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1110/001/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-24",
    last_modify_date="2025-03-24",
    mitre_version="v16",
    priority="High",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| eval event_description="More than 5 failed logons (4625) followed by a successful logon (4624)"
| table _time indextime event_description hash_sha256 user host fail_count success_time mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

[T1204.002] INFOSTEALER - Zone.Identifier ADS Write Detected
```
`indextime` (`sysmon` EventCode=15 AND TargetFilename="*Zone.Identifier*")
| stats count by _time host user Image TargetFilename ProcessId
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1204.002 - Zone.Identifier ADS Write Detected",
    mitre_category="Execution",
    mitre_technique="User Execution",
    mitre_technique_id="T1204",
    mitre_subtechnique="Malicious File",
    mitre_subtechnique_id="T1204.002",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1204/002/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-24",
    last_modify_date="2025-03-24",
    mitre_version="v16",
    priority="Medium",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(indextime)
| eval event_description="Zone.Identifier ADS write detected (Sysmon EventCode=15)"
| table _time indextime event_description hash_sha256 host user Image TargetFilename ProcessId mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

[T1059.006] INFOSTEALER - .txt File Renamed to .py and Executed
```
`indextime` (`sysmon` EventCode=11 (TargetFilename="*.txt" OR TargetFilename="*.py"))
| eval file_ext=lower(replace(TargetFilename, "^.*\.", ""))
| eval base_name=lower(replace(TargetFilename, "\.txt$|\.py$", ""))
| stats min(_time) as first_seen max(_time) as last_seen values(TargetFilename) as files_created by base_name host user
| where mvcount(files_created) > 1 AND "txt" IN file_ext AND "py" IN file_ext
| join type=inner base_name [
    search `sysmon` EventCode=1 Image="*\\py.exe" CommandLine="*.py"
    | eval base_name=lower(replace(CommandLine, "^.*\\([^\\]+)\.py.*$", "\1"))
    | rename _time as exec_time, CommandLine as executed_cmd
]
| where exec_time - last_seen <= 300  // executed within 5 minutes of rename
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1059.006 - .txt File Renamed to .py and Executed",
    mitre_category="Execution",
    mitre_technique="Command and Scripting Interpreter",
    mitre_technique_id="T1059",
    mitre_subtechnique="Python",
    mitre_subtechnique_id="T1059.006",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1059/006/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-24",
    last_modify_date="2025-03-24",
    mitre_version="v16",
    priority="High",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(first_seen) ctime(last_seen) ctime(exec_time) ctime(indextime)
| eval event_description=".txt file was renamed or recreated as .py and executed shortly after"
| table first_seen last_seen exec_time indextime event_description hash_sha256 host user files_created executed_cmd mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

[T1059.006] INFOSTEALER - Python Script Output to Desktop
```
`indextime` (`sysmon` EventCode=11 TargetFilename="*.txt" AND Image="*\\python.exe")
| stats count by _time host user Image TargetFilename CommandLine ProcessId
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1059.006/T1005 - Python Script Output to Desktop File (results)",
    mitre_category="Execution / Collection",
    mitre_technique="Command and Scripting Interpreter",
    mitre_technique_id="T1059",
    mitre_subtechnique="Python",
    mitre_subtechnique_id="T1059.006",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1059/006/",
    mitre_link_2="https://attack.mitre.org/techniques/T1005/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-24",
    last_modify_date="2025-03-24",
    mitre_version="v16",
    priority="High",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(_time) ctime(indextime)
| table _time indextime event_description hash_sha256 host user Image CommandLine TargetFilename ProcessId mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link mitre_link_2 last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

[T1071.001] INFOSTEALER - Python HTTP Server Launched
```
`indextime` (`sysmon` EventCode=1 CommandLine="*http.server*")
| stats count by _time host user Image CommandLine CurrentDirectory ProcessId
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1071.001 - Python HTTP Server Launched",
    mitre_category="Command and Control",
    mitre_technique="Application Layer Protocol",
    mitre_technique_id="T1071",
    mitre_subtechnique="Web Protocols",
    mitre_subtechnique_id="T1071.001",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1071/001/",
    creator="Cpl Iverson",
    last_tested="",
    upload_date="2025-03-24",
    last_modify_date="2025-03-24",
    mitre_version="v16",
    priority="High",
    custom_category="infostealer"
| eval indextime = _indextime
| convert ctime(_time) ctime(indextime)
| eval event_description="Python HTTP server launched (likely for C2 or staging) using `-m http.server`"
| table _time indextime event_description hash_sha256 host user Image CommandLine CurrentDirectory ProcessId mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

## References
[1]: https://www.group-ib.com/blog/clickfix-the-social-engineering-technique-hackers-use-to-manipulate-victims
[2]: https://0xmrmagnezi.github.io/malware%20analysis/LummaStealer/
