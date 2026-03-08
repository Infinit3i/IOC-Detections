---
title: Malware
---

## Executive Summary

<High-level summary of the threat. Describe what the malware/phishing kit/tool is, who it targets, and its primary impact.>

---

### Overview

<details markdown="1">
<summary><strong>description</strong></summary>

<br/>

<Type of threat: malware family / phishing kit / RAT / loader / ransomware / etc.>

**Delivery:**  
<How the threat reaches victims: phishing email, exploit, drive-by download, malicious attachment, etc.>

**Capabilities:**  
<Key behaviors such as credential harvesting, persistence, lateral movement, C2 communication, etc.>

**Notable Characteristics:**  
<Unique traits, infrastructure patterns, evasion methods, or operational characteristics.>

</details>

---

### Attack Flow

<details markdown="1">
<summary><strong>Flow</strong></summary>

<br/>

```

Initial Access → Execution → Payload Delivery → Persistence → Command & Control

```

Detailed sequence:

- `<Step 1>`
- `<Step 2>`
- `<Step 3>`
- `<Step 4>`

</details>

---

### MITRE ATT&CK Techniques

* [TXXXX – Technique Name](https://attack.mitre.org/)
* [TXXXX – Technique Name](https://attack.mitre.org/)
* [TXXXX – Technique Name](https://attack.mitre.org/)
* [TXXXX – Technique Name](https://attack.mitre.org/)

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
* [Files](<link>)

### Detection Rules

| Rule | View | Download |
|-----|-----|-----|
| YARA | [View](github like) | <a href="./RULES/LOCAL.yara" download>Download</a> |
| Suricata | [View](https://github.com/Infinit3i/IOC-Detections/blob/main/REMOTE.rules) | <a href="./RULES/LOCAL.rules" download>Download</a> |
| Splunk | [View](https://github.com/Infinit3i/IOC-Detections/blob/main/REMOTE.spl) | <a href="./RULES/LOCAL.spl" download>Download</a> |

---

## Research & References

- <https://example.com/article>
- <https://example.com/research>
- <https://example.com/report>