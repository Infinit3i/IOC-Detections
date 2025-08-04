# Phishingkit / AiTM — **Tycoon 2FA**

## Executive Summary

Tycoon 2FA is an Adversary-in-the-Middle (AiTM) **phishing kit** sold as PhaaS. It proxies Microsoft 365/Gmail logins to intercept credentials and **session cookies**, enabling MFA bypass without exploiting CVEs. sold on telegram for as low as $120

---

## MITRE ATT\&CK Techniques

* [x] **T1566.002 – Spearphishing Link** [https://attack.mitre.org/techniques/T1566/002/](https://attack.mitre.org/techniques/T1566/002/)
* [x] **T1204.001 – User Execution: Malicious Link** [https://attack.mitre.org/techniques/T1204/001/](https://attack.mitre.org/techniques/T1204/001/)
* [x] **T1557 – Adversary-in-the-Middle** [https://attack.mitre.org/techniques/T1557/](https://attack.mitre.org/techniques/T1557/)
* [x] **T1550.004 – Use of Web Session Cookie** [https://attack.mitre.org/techniques/T1550/004/](https://attack.mitre.org/techniques/T1550/004/)
* [x] **T1078 – Valid Accounts** [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)
* [x] **T1583.001 – Acquire Infrastructure: Domains** [https://attack.mitre.org/techniques/T1583/001/](https://attack.mitre.org/techniques/T1583/001/)

---

## Threat Overview

### Tycoon 2FA

**Overview:** PhaaS AiTM platform targeting M365/Gmail. Uses reverse-proxy pages to relay live logins, capture credentials + MFA challenges, and harvest session tokens for replay.
**Delivery:** Email lures (links/QRs) to branded landing pages; often fronted with CAPTCHA/traffic-filtering.
**Unique features:** Operator dashboards, rotating domains, obfuscation/link-gating to evade filters.

---

## Mitigations

* **Phishing-resistant MFA:** Enforce FIDO2/WebAuthn; phase out SMS/voice/OTP where feasible.
* **Conditional access & token hardening:** Device compliance, location/ASN/risk checks; short token lifetimes; continuous access evaluation; revoke refresh tokens on suspicion.
* **OAuth governance:** Disable user-consent by default; require admin approval; monitor new consent grants.
* **Email & domain controls:** DMARC/DKIM/SPF; block newly registered/look-alike domains; inspect QR-code attachments/links.
* **User awareness (realistic):** Teach AiTM signs but assume clicks will happen—design controls for **post-auth** detection and rapid token revocation.

---

## Detections

* [IOCs](insert-ioc-list-link)
* [Yara](insert-yara-rules-link)
* [Suricata](insert-yara-rules-link)
* [Sigma](insert-detection-rules-link)
* [Splunk](insert-detection-rules-link)

---

## Research & References

* [ ] Proofpoint — Analysis of **Tycoon 2FA** (AiTM/PhaaS overview).
* [ ] SEKOIA — **Tycoon 2FA** technical notes and IOC set (GitHub).
* [ ] Microsoft Security — Guidance on detecting/mitigating **AiTM** and session-cookie replay.
* [ ] BleepingComputer — Reporting on **MFA-bypassing phishing kits** targeting M365/Gmail (Tycoon 2FA, peers).
