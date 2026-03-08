---
title: Agent Tesla
---

## Executive Summary

Agent Tesla is a remote access trojan (RAT) written in .NET that has been actively targeting users with Microsoft Windows OS-based systems since 2014. It is a versatile malware with a wide range of capabilities, including sensitive information stealing, keylogging and screenshot capture. Since its release, this malicious software has received regular updates. It is sold as a malware-as-a-service, with several subscription options available for purchase. Campaigns involving Agent Tesla often start with phishing emails, masquerading as legitimate messages from trusted sources.

---

### Overview

**Type of threat:**  
Information-stealing Remote Access Trojan (RAT) sold as Malware-as-a-Service (MaaS).

**Delivery:**  
Primarily distributed through phishing campaigns using malicious attachments such as:

- `.zip` / `.rar` archives
- malicious Office documents with macros
- `.img` / `.iso` disk images
- `.exe`, `.js`, `.vbs`, or `.lnk` droppers

The payload is often delivered through **multi-stage loaders** such as:

- GuLoader
- Snake Keylogger loaders
- .NET downloaders
- PowerShell download chains

Attachments frequently impersonate invoices, purchase orders, shipping notices, or financial documents.

**Capabilities:**  

Agent Tesla is primarily an **information stealer and surveillance RAT** with features including:

- Credential harvesting from web browsers (Chrome, Firefox, Edge, Opera)
- Email credential theft from clients such as Outlook and Thunderbird
- FTP credential extraction
- Keylogging of user keystrokes
- Clipboard monitoring
- Screenshot capture
- System reconnaissance (hostname, IP, OS version)
- Data exfiltration via SMTP, FTP, HTTP, or Telegram APIs
- Persistence via registry Run keys or startup folders

Stolen data is periodically transmitted to attacker-controlled infrastructure.

**Notable Characteristics:**  

- Written in **.NET**, making it easy to modify and recompile
- Widely sold on underground forums as a **subscription-based MaaS tool**
- Often delivered through **commodity malware loaders**
- Heavy use of **string obfuscation, Base64 encoding, and packing**
- Frequent **variant churn** due to builder kits used by different operators
- Exfiltration frequently uses **SMTP or Telegram bots**, which helps evade traditional C2 detection

## Threat Overview

### <Threat Family Name>

- Appeared in <year> as <MaaS / malware family / toolkit>
- Primary delivery methods: <phishing, exploit kits, drive-by, etc>

#### Harvest

- Browser credentials and cookies
- Clipboard data
- Desktop screenshots
- Keystrokes

#### Obfuscation

- Steganography with payloads (images)
- Anti-debugging
- Base64 / XOR layering

#### Persistence

- `%APPDATA%`
- Registry Run Keys
- Temp directories
- Alternate Data Streams (Zone.Identifier removal)

---

### Attack Flow

Example flow:

```dark

Phishing Email → Word Attachment → Embedded RTF / Excel Object → Macro Execution → PowerShell Download → .NET Loader → Process Injection (RegSvcs.exe / RegAsm.exe) → Agent Tesla Execution → Credential Harvesting → SMTP / HTTP Exfiltration

```

Detailed sequence:

* **Phishing Email:** Victim receives an email impersonating invoices, shipping notices, or purchase orders.
* **Malicious Attachment:** Email contains a Word document or archive containing the malicious file.
* **Embedded Object Execution:** Document loads an embedded RTF or Excel object that triggers macro execution.
* **PowerShell Downloader:** Macro launches PowerShell to retrieve a remote payload.
* **.NET Loader Execution:** A .NET loader (often GuLoader or similar) downloads and decrypts the Agent Tesla payload.
* **Process Injection:** The loader injects the payload into legitimate Windows processes such as `RegSvcs.exe` or `RegAsm.exe`.
* **Agent Tesla Activation:** Malware begins credential harvesting and system reconnaissance.
* **Data Exfiltration:** Stolen credentials and system data are transmitted to attacker infrastructure via SMTP, FTP, HTTP, or Telegram APIs.
```

---

## [MITRE ATT&CK Techniques](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0331%2FS0331-enterprise-layer.json)

- <https://attack.mitre.org/techniques/T1087/001/>  
- <https://attack.mitre.org/techniques/T1071/001/>  
- <https://attack.mitre.org/techniques/T1071/003/>  
- <https://attack.mitre.org/techniques/T1560/>  
- <https://attack.mitre.org/techniques/T1547/001/>  
- <https://attack.mitre.org/techniques/T1185/>  
- <https://attack.mitre.org/techniques/T1115/>  
- <https://attack.mitre.org/techniques/T1555/>  
- <https://attack.mitre.org/techniques/T1555/003/>  
- <https://attack.mitre.org/techniques/T1140/>  
- <https://attack.mitre.org/techniques/T1048/003/>  
- <https://attack.mitre.org/techniques/T1203/>  
- <https://attack.mitre.org/techniques/T1564/001/>  
- <https://attack.mitre.org/techniques/T1564/003/>  
- <https://attack.mitre.org/techniques/T1562/001/>  
- <https://attack.mitre.org/techniques/T1105/>  
- <https://attack.mitre.org/techniques/T1056/001/>  
- <https://attack.mitre.org/techniques/T1112/>  
- <https://attack.mitre.org/techniques/T1027/>

---

## Mitigations

* **Identity protections:** <Example mitigation>
* **Endpoint controls:** <Example mitigation>
* **Network monitoring:** <Example mitigation>
* **User awareness:** <Example mitigation>

---

## Detections

### Indicators of Compromise (IOCs)

* [IPs](<link>)
* [Domains](<link>)
* [URLs](<link>)
* [MD5](<link>)
* [SHA1](<link>)
* [SHA256](<link>)

### Detection Rules

* [YARA](<link>)
* [Suricata](<link>)
* [Sigma](<link>)
* [Splunk](<link>)

---

## Research & References

## Research & References
- <https://example.com/article-1>
- https://any.run/malware-trends/agenttesla/
- https://attack.mitre.org/software/S0331/
- https://www.fortinet.com/blog/threat-research/agent-tesla-variant-spread-by-crafted-excel-document
- https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla


