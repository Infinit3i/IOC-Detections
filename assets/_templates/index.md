---
layout: malware
title: Example Stealer

start_date: 2023
last_updated: 2025

executive_summary: Example infostealer targeting browsers and crypto wallets.

overview:
  type: Infostealer
  delivery: Phishing attachments and cracked software downloads
  capabilities: Credential theft, crypto wallet harvesting, screenshot capture
  characteristics: Uses Telegram C2 infrastructure

attack_flow:
  diagram: "Initial Access → Execution → Payload Delivery → Persistence → C2"
  steps:
    - User downloads malicious file
    - Loader executes payload
    - Malware establishes persistence
    - Data is exfiltrated to C2

mitre:
  - id: T1566
    name: Phishing
    link: https://attack.mitre.org/techniques/T1566/

static_analysis:
  - Packed sample
  - WinHTTP imports present
  - Embedded strings reveal C2 pattern

dynamic_analysis:
  - Creates persistence
  - Spawns child process
  - Connects to remote infrastructure

mitigations:
  - name: Identity protections
    value: Enforce MFA
  - name: Endpoint controls
    value: Block unsigned scripts
  - name: Network monitoring
    value: Alert on suspicious outbound traffic
  - name: User awareness
    value: Train against phishing attachments

iocs:
  urls: /iocs/urls
  files: /iocs/files
  domains: /iocs/domains
  ips: /iocs/ips
  sha1: /iocs/sha1
  sha256: /iocs/sha256
  md5: /iocs/md5

rules:
  yara:
    view: https://github.com/example/yara
    download: ./RULES/sample.yara
  sigma:
    view: https://github.com/example/sigma
    download: ./RULES/sample.yml
  suricata:
    view: https://github.com/example/suricata
    download: ./RULES/sample.rules
  spl:
    view: https://github.com/example/spl
    download: ./RULES/sample.spl

references:
  - https://example.com/report
---