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
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - Encoded PowerShell command detected",
    mitre_category="Defense_Evasion",
    mitre_technique="Browser History and Autofill Data Exfiltration",
    mitre_technique_id="XXXXX",
    mitre_subtechnique="",
    mitre_subtechnique_id="",
    apt="",
    mitre_link="",
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

### SPL/Sysmon - Encoded Powershell command [1]

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

[TXXXX] Hidden Powershell
```
`indextime` `powershell` (process_name="powershell.exe" OR command_line="*powershell.exe*")
    AND command_line="*-W Hidden*"
    AND command_line="*Invoke-WebRequest*"
    AND command_line="*/uploads/*"
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

ALL T1204.002 already added

https://attack.mitre.org/techniques/T1010/
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

https://attack.mitre.org/techniques/T1010/
```
`indextime` (`sysmon` EventCode="1") OR (`windows-security` EventCode="4688")
| where CommandLine LIKE "%Get-Process%" AND CommandLine LIKE "%mainWindowTitle%"
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - Suspicious process enumeration using Get-Process and mainWindowTitle",
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

(CHECK) T1010 - Analytic 1 - Suspicious Commands
```
`indextime` `powershell` EventCode="4103" 
| where CommandLine LIKE "%Get-Process%" AND CommandLine LIKE "%mainWindowTitle%"
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - Analytic 1 - Suspicious Commands",
    mitre_category="Discovery",
    mitre_technique="",
    mitre_technique_id="TXXXX",
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
(CHECK) T1010 - Analytic 1 - Suspicious Processes
```
`indextime` (`sysmon` EventCode="1") OR (`windows-security` EventCode="4688") 
| where CommandLine LIKE "%Get-Process%" AND CommandLine LIKE "%mainWindowTitle%"
| eval hash_sha256=lower(hash_sha256),
    hunting_trigger="INFOSTEALER - Analytic 1 - Suspicious Processes",
    mitre_category="Discovery",
    mitre_technique="",
    mitre_technique_id="TXXXX",
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

# Named Tunnel
```
```
Cobalt Strike (MSSE-*)
Meterpreter (postex)
Impacket (srvsvc)
```
`sysmon` EventCode=17
| where match(Pipe, ".*\\\\pipe\\\\(msse-|postex|srvsvc).*")
```



```
`sysmon` EventCode=13
| timechart span=1m count by Image
| eventstats avg(count) as avg_count, stdev(count) as stddev_count
| eval threshold=(avg_count + (2 * stddev_count))
| where count > threshold
```





## References
[1]: https://www.group-ib.com/blog/clickfix-the-social-engineering-technique-hackers-use-to-manipulate-victims
[2]: https://0xmrmagnezi.github.io/malware%20analysis/LummaStealer/
