# Rules for Info Stealers



### SPL/Sysmon - Suspicious File Access and Modifications

```
`sysmon` EventID=11 TargetFilename IN ("*\\Chrome\\User Data\\Default\\Cookies", "*\\Edge\\User Data\\Default\\Cookies")
```

### SPL/Sysmon - Suspicious Process Execution

```
`sysmon` EventID=1 Image="*python.exe" CommandLine="*decrypt_value*"
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
`powershell`
    (process_name="powershell.exe" OR command_line="*powershell.exe*")
    AND (command_line="*-enc *" OR command_line="*-EncodedCommand *")
```


```
`powershell`
    (process_name="powershell.exe" OR command_line="*powershell.exe*")
    AND command_line="*-W Hidden*"
    AND command_line="*Invoke-WebRequest*"
    AND command_line="*/uploads/*"
```

```
`sysmon` (process_name="mshta.exe" OR command_line="*mshta*") AND (command_line="*http://*" OR command_line="*https://*")
```

ALL T1204.002 already added

```
`powershell` EventCode="4103" 
| where CommandLine LIKE "%Get-Process%" AND CommandLine LIKE "%mainWindowTitle%"
```

```
`sysmon` EventCode="1") OR (`windows-security` EventCode="4688") 
| where CommandLine LIKE "%Get-Process%" AND CommandLine LIKE "%mainWindowTitle%"
```



## References
[1]: https://www.group-ib.com/blog/clickfix-the-social-engineering-technique-hackers-use-to-manipulate-victims
[2]: https://0xmrmagnezi.github.io/malware%20analysis/LummaStealer/
