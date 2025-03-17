# InfoStealers

# Executive Summary
Fake Captcha are being use gather end user credentials. Main expliot path for USMC is phishing.

![Lumma Stealer Attack Path](https://github.com/Infinit3i/8DCO-IDM-Detections/blob/e2438a6937ef1919b619f641e1482cea7238dc50/InfoStealers/Pictures/Lumma_stealer_attack_path.png)

-----



### T-Codes
- [x] https://attack.mitre.org/techniques/T0882/
- [x] https://attack.mitre.org/techniques/T1204/002/
- [x] https://attack.mitre.org/techniques/T1115
- [x] https://attack.mitre.org/techniques/T1112
- [x] https://attack.mitre.org/techniques/T1010
- [x] https://attack.mitre.org/techniques/T1012
- [x] https://attack.mitre.org/techniques/T1129
- [x] https://attack.mitre.org/techniques/T1129
- [x] https://attack.mitre.org/techniques/T1497/001
- [x] https://attack.mitre.org/techniques/T1055/003
- [x] https://attack.mitre.org/techniques/T1027
- [x] https://attack.mitre.org/techniques/T1140

### Lumma

Lumma Stealer (aka LummaC2 Stealer) is an information stealer that has been available through a Malware-as-a-Service (MaaS) model on Russian-speaking forums since at least August 2022. Once the targeted data is obtained, it is exfiltrated to a C2 server.

### Peaklight [2]

Mandiant identified a new memory-only dropper using a complex, multi-stage infection process. This memory-only dropper decrypts and executes a PowerShell-based downloader. This PowerShell-based downloader is being tracked as PEAKLIGHT.


# user training
- Users should verify URLs in emails, especially from unknown or unexpected sources.
- Users should avoid downloading cracked software, illegal material or visiting suspicious websites.
- Users should not click on links from suspicious sources.
- Users should adopt strong password practices: change passwords regularly, use unique and robust passwords for each online account, and include a combination of uppercase and lowercase letters, numbers, and symbols. And use 2FA when it is supported.
- Users should not store or save passwords in web browsers, clear text files, windows credential managers. Use password managers instead.

# Mitigations - G6
- Organizations should implement advanced endpoint detection and response (EDR) solutions that use behavior-based detection techniques to identify and block malicious activities. Ensure AV and/or EDR perform sandboxing of the executable files downloaded from the internet.
- Organizations should implement MFA for accessing sensitive systems and data.
- Organizations should conduct regular training sessions to educate users about social engineering tactics and new phishing schemes.
- Organizations should implement robust email filtering to block phishing emails and malicious attachments.
- Organizations should apply a strict software execution policy to prevent users from downloading malware disguised as fake software installers.
- Organization should implement application whitelisting solutions to allow only legitimate applications or scripts to run via the mshta.exe process.
- Organizations should deploy Group Policy to enforce the firewall rule across all endpoints to prevent outbound connection over 443 or 80 ports established by the mshta.exe process (Ensure that no legitimate business processes rely on mshta.exe to make network connections over port 443/80).
- Organizations should block IOCs shared by threat intelligence service providers.


# Detections - DCO

- [DCO Rules](https://github.com/Infinit3i/8DCO-IDM-Detections/blob/6681c47a600d7ff34db7e964836de473c7ecc76a/InfoStealers/rules.md)
- [DCO IOCs](https://github.com/Infinit3i/8DCO-IDM-Detections/blob/6681c47a600d7ff34db7e964836de473c7ecc76a/InfoStealers/ioc.md)
- [DCO Yara](https://github.com/Infinit3i/8DCO-IDM-Detections/blob/6681c47a600d7ff34db7e964836de473c7ecc76a/InfoStealers/yara.md)



---




[2]: https://cloud.google.com/blog/topics/threat-intelligence/peaklight-decoding-stealthy-memory-only-malware/


TODO
- https://www.rapid7.com/blog/post/2024/08/12/ongoing-social-engineering-campaign-refreshes-payloads/
- https://research.checkpoint.com/2024/stargazers-ghost-network/
- https://www.fortinet.com/blog/threat-research/exploiting-cve-2024-21412-stealer-campaign-unleashed
- https://censys.com/a-beginners-guide-to-hunting-open-directories/
- https://www.mcafee.com/blogs/other-blogs/mcafee-labs/clickfix-deception-a-social-engineering-tactic-to-deploy-malware/
- https://blog.sekoia.io/exposing-fakebat-loader-distribution-methods-and-adversary-infrastructure/
- https://www.0x1c.zip/0001-lummastealer/
- https://www.trellix.com/blogs/research/how-attackers-repackaged-a-threat-into-something-that-looked-benign/
- https://www.proofpoint.com/us/blog/threat-insight/clipboard-compromise-powershell-self-pwn
- https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion
- https://www.esentire.com/blog/fake-browser-updates-delivering-bitrat-and-lumma-stealer
- https://viuleeenz.github.io/posts/2024/03/understanding-api-hashing-and-build-a-rainbow-table-for-lummastealer/
- https://www.malware-traffic-analysis.net/2024/03/07/index.html
- https://www.paloaltonetworks.com/blog/security-operations/a-deep-dive-into-malicious-direct-syscall-detection/
- https://gridinsoft.com/spyware/lumma-stealer
- https://viuleeenz.github.io/posts/2024/02/understanding-peb-and-ldr-structures-using-ida-and-lummastealer/
- https://any.run/cybersecurity-blog/crackedcantil-breakdown/
- https://info.spamhaus.com/hubfs/Botnet%20Reports/Q4%202023%20Botnet%20Threat%20Update.pdf
- https://www.youtube.com/watch?v=lmMA4WYJEOY&ab_channel=EmbeeResearch
- https://www.fortinet.com/blog/threat-research/lumma-variant-on-youtube
- https://outpost24.com/blog/lummac2-anti-sandbox-technique-trigonometry-human-detection/
- https://g0njxa.medium.com/approaching-stealers-devs-a-brief-interview-with-lummac2-94111d4b1e11
- https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks
- https://www.intrinsec.com/lumma_stealer_actively_deployed_in_multiple_campaigns/
- https://www.esentire.com/blog/the-case-of-lummac2-v4-0
- https://darktrace.com/blog/the-rise-of-the-lumma-info-stealer
- https://www.rapid7.com/blog/post/2023/08/31/fake-update-utilizes-new-idat-loader-to-execute-stealc-and-lumma-infostealers/
- https://outpost24.com/blog/everything-you-need-to-know-lummac2-stealer/
- https://medium.com/s2wblog/lumma-stealer-targets-youtubers-via-spear-phishing-email-ade740d486f7
- https://www.cloudsek.com/blog/threat-actors-abuse-ai-generated-youtube-videos-to-spread-stealer-malware
