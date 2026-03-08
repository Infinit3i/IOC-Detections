---
title: XWorm
---

## Executive Summary

XWorm is a .NET-based remote access trojan (RAT) commonly delivered through phishing campaigns and multi-stage infection chains. It is used for remote control, credential theft, payload execution, and command-and-control (C2) communications. In observed campaigns, delivery may involve malicious Office content, exploitation of older Office vulnerabilities, PowerShell execution, in-memory .NET loaders, and process hollowing before the final XWorm payload connects to attacker infrastructure.

---

### Overview

<details markdown="1">
<summary><strong>description</strong></summary>

<br/>

Remote Access Trojan (RAT) / commodity malware.

**Delivery:**  
Phishing emails with attached Excel or Office documents, embedded OLE objects, and exploit-assisted delivery chains.

**Capabilities:**  
Remote control, payload execution, credential theft, persistence, process injection/hollowing, and C2 communications.

**Notable Characteristics:**  
Observed chains may involve CVE-2018-0802, PowerShell execution, fileless or in-memory .NET stages, and process hollowing before XWorm is loaded.

</details>

<br/>

---

### Attack Flow

<details markdown="1">
<summary><strong>Flow</strong></summary>

<br/>

```dark
Phishing Email → Attached Excel File → Embedded OLE Object → CVE-2018-0802 / HTA Retrieval → PowerShell Execution → Fileless .NET Loader → XWorm Payload Download → Process Hollowing → XWorm RAT Load → C2 Connection
````

Detailed sequence:

* Victim receives a phishing email with an attached Excel or Office document.
* The document contains an embedded OLE object or exploit path that triggers execution.
* A malicious HTA file may be retrieved through exploitation of CVE-2018-0802.
* PowerShell is executed to download or launch the next stage.
* A fileless or in-memory .NET loader retrieves the XWorm payload.
* The malware performs process hollowing or process injection to evade detection.
* XWorm is loaded and establishes command-and-control communication.

</details>

<br/>

---

### MITRE ATT&CK Techniques

<details markdown="1">
<summary><strong>Techniques</strong></summary>

* [T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
* [T1070.004 – Indicator Removal: File Deletion](https://attack.mitre.org/techniques/T1070/004/)
* [T1053.005 – Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
* [T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
* [T1566.001 – Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
* [T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
* [T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
* [T1562 – Impair Defenses](https://attack.mitre.org/techniques/T1562/)
* [T1136 – Create Account](https://attack.mitre.org/techniques/T1136/)

</details>
<br/>

---

## Mitigations

* **Identity protections:** Enforce MFA, monitor suspicious account changes, and restrict creation of unauthorized accounts.
* **Endpoint controls:** Block Office child-process execution, restrict PowerShell abuse, and monitor process injection behavior.
* **Network monitoring:** Alert on suspicious outbound C2 traffic and staged payload retrieval.
* **User awareness:** Train users to avoid malicious attachments and suspicious Office documents.

---

## Detections

### Indicators of Compromise (IOCs)

| IOC Type | View | Download |
|---------|------|----------|
| IPs | [View](https://github.com/Infinit3i/IOC-Detections/blob/main/XWorm/IOCs/XWorm_ip.csv) | <a href="./IOCs/XWorm_ip.csv" download>Download</a> |
| Domains | [View](https://github.com/Infinit3i/IOC-Detections/blob/main/XWorm/IOCs/XWorm_domain.csv) | <a href="./IOCs/XWorm_domain.csv" download>Download</a> |
| URLs | [View](https://github.com/Infinit3i/IOC-Detections/blob/main/XWorm/IOCs/XWorm_url.csv) | <a href="./IOCs/XWorm_url.csv" download>Download</a> |
| MD5 | [View](https://github.com/Infinit3i/IOC-Detections/blob/main/XWorm/IOCs/XWorm_md5.csv) | <a href="./IOCs/XWorm_md5.csv" download>Download</a> |
| SHA1 | [View](https://github.com/Infinit3i/IOC-Detections/blob/main/XWorm/IOCs/XWorm_sha1.csv) | <a href="./IOCs/XWorm_sha1.csv" download>Download</a> |
| SHA256 | [View](https://github.com/Infinit3i/IOC-Detections/blob/main/XWorm/IOCs/XWorm_sha256.csv) | <a href="./IOCs/XWorm_sha256.csv" download>Download</a> |
| Files | [View](https://github.com/Infinit3i/IOC-Detections/blob/main/XWorm/IOCs/XWorm_files.csv) | <a href="./IOCs/XWorm_files.csv" download>Download</a> |

### Detection Rules

| Rule     | View                                                                       | Download                                            |
| -------- | -------------------------------------------------------------------------- | --------------------------------------------------- |
| YARA     | [View](github like)                                                        | <a href="./RULES/LOCAL.yara" download>Download</a>  |
| Suricata | [View](https://github.com/Infinit3i/IOC-Detections/blob/main/REMOTE.rules) | <a href="./RULES/LOCAL.rules" download>Download</a> |
| Splunk   | [View](https://github.com/Infinit3i/IOC-Detections/blob/main/REMOTE.spl)   | <a href="./RULES/LOCAL.spl" download>Download</a>   |

---

## Research & References

* [attack-chain-leads-to-xworm-and-agenttesla](https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla)
