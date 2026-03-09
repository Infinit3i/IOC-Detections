
**sigma rule for sus graph api usage by non-outlook process**
```sigma
title: Suspicious Graph API Usage from Unusual Processes
id: 12345678-1234-1234-1234-123456789abc
status: experimental
description: |
  Detects HTTP/HTTPS requests to graph.microsoft.com in Sysmon event logs
  when the originating process is not one of the typical Microsoft Office processes (e.g., outlook.exe).
author: Your Name
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    CommandLine|contains: "graph.microsoft.com"
  filtering:
    # Allow known office executables, tweek as necessary for your environment.
    ProcessName|endswith:
      - "\outlook.exe"
      - "\officeclicktocall.exe"
  condition: selection and not filtering
falsepositives:
  - Legitimate automated Office integrations or service accounts
level: high

```
copl: - This rule monitors Sysmon event logs for HTTP requests targeting the Microsoft Graph API endpoints when they originate from processes not typically associated with legitimate Office applications, such as processes other than `outlook.exe`. Its goal is to flag abnormal command-and-control communication that may indicate malicious exploitation of the Graph API.

**sigma sus icmp activity from mspaint**
```sigma
title: Suspicious ICMP Activity from mspaint.exe
id: abcdef12-3456-7890-abcd-ef1234567890
status: experimental
description: |
  Detects Sysmon network events (EventID 3) where the process image is mspaint.exe
  and the protocol used is ICMP, which is unusual for the MS Paint process.
author: Your Name
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 3
    Image|endswith: "\mspaint.exe"
    Protocol: ICMP
  condition: selection
falsepositives:
  - Rare legitimate diagnostic tools or scanning software
level: high

```
copl: This rule examines Sysmon network events to detect when `mspaint.exe`—a process not ordinarily involved in networking—is observed generating ICMP traffic. Since mspaint is generally not expected to perform network communications, such behavior is flagged as suspicious and may signal covert or fileless activity associated with adversary tools.


---

```ad-faq
title: my wip rules based on above
```
**splunk saved search detecting strange mspaint activities**
```SPL
index=win_sysmon EventCode=10 ParentUser="NT AUTHORITY\\SYSTEM" process_name=*
| stats count by _time, ParentUser, ParentImage, process_name, EventCode 
| where ParentImage!="C:\\Windows\\explorer.exe" AND ParentImage!="C:\\Windows\\System32\\cmd.exe" 
| rename process_name as ProcessName 
| table _time, ParentUser, ParentImage, ProcessName, EventCode

```

```ad-info
title: suggested copilot change to above
```

```SPL
index=win_sysmon EventCode=* ParentUser="NT AUTHORITY\\SYSTEM" process_name=*
| where ParentImage!="C:\\Windows\\explorer.exe" AND ParentImage!="C:\\Windows\\System32\\cmd.exe"
| rename process_name as ProcessName, _time as EventTime
| dedup _time, ParentUser, ParentImage, ProcessName, EventCode
| table _time, ParentUser, ParentImage, ProcessName, EventCode
```
