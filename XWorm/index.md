---
layout: default
title: XWorm
---

# XWorm

## Executive Summary
<Insert high-level summary of the malware type, attack vectors, and impact.>

![Attack Path Diagram](<insert-image-or-diagram-link-here>)
- phishing email
- attached excel file
- ole object that has executable inside
- CVE-2018-0802 *downloaded HTA file
- executes powershell
- downloads fileless .net
-download xworm payload
- process hollow payload
- load xworm RAT
- connect to C2

date of earliest attack in the wild
date of latest attack in the wild

---

## MITRE ATT&CK Techniques
- [x] <https://attack.mitre.org/techniques/TXXXX/>

---

## Threat Overview

### <Threat Family 1>
<Insert overview of malware family, origin, delivery method, and unique features.>

### <Threat Family 2>
<Insert similar details for any related or emerging variants.>

---

## User Training & Awareness
- 

---

## Mitigations
- 

---

## Detections
- [IOCs](<insert-ioc-list-link>)
- [Yara](<insert-yara-rules-link>)
- [Suricata](<insert-yara-rules-link>)
- [Sigma](<insert-detection-rules-link>)
- [Splunk](<insert-detection-rules-link>)

---

## Research & References
- [ ] <https://example.com/article-1>