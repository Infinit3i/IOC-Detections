# InfoStealers

### Stage 1
- https://attack.mitre.org/techniques/T0882/
- https://attack.mitre.org/techniques/T1204/002/

### Stage 2
- https://attack.mitre.org/techniques/T1115
- https://attack.mitre.org/techniques/T1112
- https://attack.mitre.org/techniques/T1010
- https://attack.mitre.org/techniques/T1012
- https://attack.mitre.org/techniques/T1129

### Stage 3
- https://attack.mitre.org/techniques/T1129
- https://attack.mitre.org/techniques/T1497/001
- https://attack.mitre.org/techniques/T1055/003
- https://attack.mitre.org/techniques/T1027
- https://attack.mitre.org/techniques/T1140


### Lumma

Lumma Stealer (aka LummaC2 Stealer) is an information stealer that has been available through a Malware-as-a-Service (MaaS) model on Russian-speaking forums since at least August 2022. Once the targeted data is obtained, it is exfiltrated to a C2 server.

###


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










