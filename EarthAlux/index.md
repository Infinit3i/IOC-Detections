---
layout: malware
title: Earth Alux

start_date: "2024"
last_updated: "2026"

executive_summary: >
  Earth Alux and APT41 are advanced China-linked threat actors that employ
  multi-stage, modular toolkits using techniques such as fileless execution,
  web shell exploitation, and diverse command-and-control channels to evade
  traditional defenses. They target strategic sectors including government,
  technology, and industrial organizations and conduct campaigns that combine
  espionage objectives with financially motivated operations.

  APT41 is a well-established group with a long operational history and a broad
  portfolio of activity including both cyber espionage and cybercrime. Over
  time it has developed a flexible and evolving attack playbook.

  Earth Alux appears to be a newer adversary that leverages a specialized
  toolkit including Godzilla, VARGEIT, and COBEACON. The group has demonstrated
  unusual techniques such as loading tools filelessly into processes like
  mspaint.exe, suggesting a more focused and specialized operational approach.

overview:
  delivery: Web shell exploitation, compromised infrastructure, multi-stage loaders
  capabilities: Fileless execution, modular malware deployment, command-and-control communication, espionage operations
  characteristics: >
    Uses specialized tooling such as Godzilla, VARGEIT, and COBEACON. Known for
    injecting tools into legitimate processes including mspaint.exe and using
    modular components for stealthy operations.

attack_flow:
  diagram: "Initial Access → Web Shell → Fileless Loader → Modular Payload → Command & Control"
  steps:
    - Initial compromise of exposed infrastructure
    - Deployment of web shell access
    - Fileless loading of tooling into legitimate processes
    - Execution of modular toolkit components
    - Establishment of command-and-control communications

mitre:

static_analysis: []

dynamic_analysis: []

mitigations: []

user_training:
  - Awareness of spear-phishing campaigns and malicious attachments
  - Training on suspicious infrastructure access patterns

iocs:
  urls: ""
  files: ""
  domains: ""
  ips: ""
  sha1: ""
  sha256: ""
  md5: ""

rules:
  yara:
    view: ""
    download: ""
  sigma:
    view: ""
    download: ""
  suricata:
    view: ""
    download: ""
  spl:
    view: ""
    download: ""

references:
  - https://www.trendmicro.com/en_us/research/25/c/the-espionage-toolkit-of-earth-alux.html
---