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
- Implement multi-factor authentication (MFA) across all account types, including default, local, domain, and cloud accounts, to prevent unauthorized access, even if credentials are compromised. MFA provides a critical layer of security by requiring multiple forms of verification beyond just a password. This measure significantly reduces the risk of adversaries abusing valid accounts to gain initial access, escalate privileges, maintain persistence, or evade defenses within your network.
- Organizations should conduct regular training sessions to educate users about social engineering tactics and new phishing schemes.
- Organizations should implement robust email filtering to block phishing emails and malicious attachments.
- Organizations should apply a strict software execution policy to prevent users from downloading malware disguised as fake software installers.
- Organization should implement application whitelisting solutions to allow only legitimate applications or scripts to run via the mshta.exe process.
- Organizations should deploy Group Policy to enforce the firewall rule across all endpoints to prevent outbound connection over 443 or 80 ports established by the mshta.exe process (Ensure that no legitimate business processes rely on mshta.exe to make network connections over port 443/80).
- Organizations should block IOCs shared by threat intelligence service providers.
- Use conditional access policies to block logins from non-compliant devices or from outside defined organization IP ranges.
- Applications and appliances that utilize default username and password should be changed immediately after the installation, and before deployment to a production environment.[83] When possible, applications that use SSH keys should be updated periodically and properly secured. Policies should minimize (if not eliminate) reuse of passwords between different user accounts, especially employees using the same credentials for personal accounts that may not be defended by enterprise security resources.
- Audit domain and local accounts as well as their permission levels routinely to look for situations that could allow an adversary to gain wide access by obtaining credentials of a privileged account. These audits should also include if default accounts have been enabled, or if new local accounts are created that have not been authorized. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers.
- Data loss prevention can be detect and block sensitive data being uploaded to web services via web browsers.
- Web proxies can be used to enforce an external network communication policy that prevents use of unauthorized external services.
- Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware or unusual data transfer over known protocols like FTP can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.


# Detections - DCO

- 30+ Spl Queries
- [DCO Rules](https://github.com/Infinit3i/8DCO-IDM-Detections/blob/6681c47a600d7ff34db7e964836de473c7ecc76a/InfoStealers/rules.md)
- 208 IOCs
- [DCO IOCs](https://github.com/Infinit3i/8DCO-IDM-Detections/blob/6681c47a600d7ff34db7e964836de473c7ecc76a/InfoStealers/ioc.md)
- 2 yara rules
- [DCO Yara](https://github.com/Infinit3i/8DCO-IDM-Detections/blob/6681c47a600d7ff34db7e964836de473c7ecc76a/InfoStealers/yara.md)


---

[1][2][3][4][5][6][7]



[1]: https://securelist.com/angry-likho-apt-attacks-with-lumma-stealer/115663/
[2]: https://cloud.google.com/blog/topics/threat-intelligence/peaklight-decoding-stealthy-memory-only-malware/
[3]: https://www.mcafee.com/blogs/other-blogs/mcafee-labs/behind-the-captcha-a-clever-gateway-of-malware/
[4]: https://denwp.com/dissecting-lumma-malware/
[5]: https://cloud.google.com/blog/topics/threat-intelligence/peaklight-decoding-stealthy-memory-only-malware/
[6]: https://www.rapid7.com/blog/post/2024/08/12/ongoing-social-engineering-campaign-refreshes-payloads/
[7]: https://www.fortinet.com/blog/threat-research/exploiting-cve-2024-21412-stealer-campaign-unleashed
[8]: https://www.mcafee.com/blogs/other-blogs/mcafee-labs/clickfix-deception-a-social-engineering-tactic-to-deploy-malware/
[9]: https://0xmrmagnezi.github.io/malware%20analysis/LummaStealer/
[10]: https://github.com/bgd-cirt/LummaStealer-YARA-Rules/blob/main/README.md
[11]: https://github.com/SEKOIA-IO/Community/blob/main/IOCs/stealc/yara_rules/infostealer_stealc_standalone.yar
[12]: https://www.0x1c.zip/0001-lummastealer/
[13]: https://www.trellix.com/blogs/research/how-attackers-repackaged-a-threat-into-something-that-looked-benign/
[14]: https://www.proofpoint.com/us/blog/threat-insight/clipboard-compromise-powershell-self-pwn
[15]: https://www.virustotal.com/gui/collection/0d487b996555e03ea2853d24c805a473822fafd7da683ab2123d0f1e688001b8
[16]: https://www.esentire.com/blog/fake-browser-updates-delivering-bitrat-and-lumma-stealer
