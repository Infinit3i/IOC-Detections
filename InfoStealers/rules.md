# Rules for Info Stealers



[] Suspicious File Access and Modifications

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

[] Suspicious Process Execution
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

[] Encoded Powershell command [1]
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

[] Hidden Powershell
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

[] 
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

[] 
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

[T1010] Suspicious Process Enumeration via Get-Process and mainWindowTitle
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

(CHECK) T1012 - Analytic 1 - Suspicious Commands

```
`indextime` ('powershell' EventCode="4103") 
| where CommandLine LIKE "%New-PSDrive%" AND (CommandLine LIKE "%Registry%" OR CommandLine LIKE "%HKEY_CLASSES_ROOT%" OR CommandLine LIKE "%HKCR%")
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1012 - Analytic 1 - Suspicious Commands",
    mitre_category="Discovery",
    mitre_technique="",
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

(CHECK) T1012 - Analytic 1 - Suspicious Processes with Registry keys
```
`indextime` (`sysmon` EventCode="1") OR (`windows-security` EventCode="4688") 
| search (CommandLine LIKE "%reg%" AND CommandLine LIKE "%query%") OR (CommandLine LIKE "%Registry%" AND (CommandLine LIKE "%HKEY_CLASSES_ROOT%" OR CommandLine "%HKCR%"))
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1012 - Analytic 1 - Suspicious Commands",
    mitre_category="Discovery",
    mitre_technique="",
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

(CHECK) T1012 - Analytic 2 - reg.exe spawned from suspicious cmd.exe
```
`indextime` ((`sysmon` EventCode="1") OR (`windows-security` EventCode="4688") 
| where (Image LIKE "%reg.exe%" AND ParentImage LIKE "%cmd.exe%")
| rename ProcessParentGuid as guid
| join type=inner guid[ 
| search ((`sysmon` EventCode="1") OR (`windows-security` EventCode="4688") AND (Image LIKE "%cmd.exe%" AND ParentImage NOT LIKE "%explorer.exe%")
| rename ProcessGuid as guid ]
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1012 - Analytic 2 - reg.exe spawned from suspicious cmd.exe",
    mitre_category="Discovery",
    mitre_technique="",
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
(CHECK) T1012 - Analytic 3 - Rare LolBAS command lines
```
`indextime` ((`sysmon` EventCode="1") OR (`windows-security` EventCode="4688") AND Image IN ('FilePathToLolbasProcess01.exe','FilePathToLolbasProcess02.exe') AND number_standard_deviations = 1.5
| select Image, ProcessCount, AVG(ProcessCount) Over() - STDEV(ProcessCount) Over() * number_standard_deviations AS LowerBound 
| WHERE ProcessCount < LowerBound
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1012 - Analytic 1 - Suspicious Commands",
    mitre_category="Discovery",
    mitre_technique="",
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

(CHECK) T1012 - Analytic 1 - Suspicious Registry
```
`indextime` (`windows-security` EventCode IN (4663, 4656)) AND ObjectType="Key" 
| where ObjectName LIKE "%SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall%" AND (UserAccessList LIKE "%4435%" OR UserAccessList LIKE "%Enumerate sub-keys%" OR UserAccessList LIKE "%4432%" OR UserAccessList LIKE "%Query key value%") AND Image NOT IN ('FilePathToExpectedProcess01.exe','FilePathToExpectedProcess02.exe')
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1012 - Analytic 1 - Suspicious Registry",
    mitre_category="Discovery",
    mitre_technique="",
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

[I1570] Detection: Suspicious Named Pipe Creation (Cobalt Strike, Meterpreter, Impacket)
```
```
Cobalt Strike (MSSE-*)
Meterpreter (postex)
Impacket (srvsvc)
```
`indextime` `sysmon` EventCode=17
| where match(Pipe, ".*\\\\pipe\\\\(msse-|postex|srvsvc).*")
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1570 - Named Pipes Associated with C2",
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
| table _time indextime event_description hash_sha256 host_fqdn user_name Pipe Image ProcessId ProcessGuid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`

```


[I1012] Spike in Registry Access (Potential Pre-Reverse Shell Activity)
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

[I1012] High Volume Registry Access (TargetObject Enumeration)
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

[T1059] Python Script Execution Logging to “results” File (Suspicious Scripting Activity)
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

[T1012] Registry Modification Spike Indicative of Enumeration or Pre-Execution Behavior
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

[T1570] Named Pipe Creation Linked to Post-Exploitation Frameworks (msse-, postex, srvsvc)
```
`indextime` `sysmon` EventCode=17
| where match(Pipe, ".*\\\\pipe\\\\(msse-|postex|srvsvc).*")
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1570 - Analytic 1 - Suspicious Named Pipe Activity",
    mitre_category="Lateral Movement",
    mitre_technique="Lateral Tool Transfer",
    mitre_technique_id="T1570",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="https://attack.mitre.org/techniques/T1570/",
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

[T1555.003] Unauthorized Access to Browser Credential Stores (SQLite: Cookies, History, Web Data)
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

[T1041] High-Volume HTTP/S Exfiltration Attempt via Suspicious Process
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

[T1570] Named Pipe Creation for Browser Data Exfiltration via Chrome, Edge, or SQLite
```
`indextime` `sysmon` EventCode=17
| search Pipe="*Chrome*" OR Pipe="*Edge*" OR Pipe="*sqlite*"
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - T1570 - Suspicious Named Pipe Activity",
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
| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link last_tested creator upload_date last_modify_date mitre_version priority custom_category
| collect `jarvis_index`
```

[T1059.006] Detect Execution of Python Infostealer
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

[T1555.003] Detect Access to Browser Credential Storage
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

[T1012] Detect Registry Modification for Browser Decryption Key
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

[T1036.003] Detection: File Renamed or Created as .py (Suspicious Python Script Drop)
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

[T1059] Python Script Execution (Suspicious Results File Usage)
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

[T1555] Browser Credential File Access
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

[T1012] Registry Key Access (Browser Master Key)
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

[T1041] Exfiltration over Network (HTTP/HTTPS burst)
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


## References
[1]: https://www.group-ib.com/blog/clickfix-the-social-engineering-technique-hackers-use-to-manipulate-victims
[2]: https://0xmrmagnezi.github.io/malware%20analysis/LummaStealer/
