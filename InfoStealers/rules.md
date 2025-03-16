# Rules for Info Stealers



### SPL/Sysmon - Suspicious File Access and Modifications

```
EventID=11  # File creation event
TargetFilename IN ("*\\Chrome\\User Data\\Default\\Cookies", "*\\Edge\\User Data\\Default\\Cookies")
```

### SPL/Sysmon - Suspicious Process Execution

```
EventID=1  # Process creation event
Image="*python.exe" # Detect Python scripts execution
CommandLine="*decrypt_value*"
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
EventID=11  # File modification or access event
TargetFilename IN ("*\\Chrome\\User Data\\Default\\History", "*\\Edge\\User Data\\Default\\History")

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
`sysmon`
  (process_name="mshta.exe" OR command_line="*mshta*")
  AND (command_line="*http://*" OR command_line="*https://*")
```


## References
[1]: https://www.group-ib.com/blog/clickfix-the-social-engineering-technique-hackers-use-to-manipulate-victims
[2]: https://0xmrmagnezi.github.io/malware%20analysis/LummaStealer/