
> 🎯 **Objective**: Identify covert APT27 activity in the environment, focusing on **webshell deployment**, **credential access**, and **C2 infrastructure masquerading as legitimate services** (e.g., HTTPS, Outlook traffic).

APT27 is known to target government and defense contractors, often leveraging **public-facing web servers** for initial access, then pivoting internally via **credential theft** and **custom malware** like `HttpBrowser` or `SysUpdate`.

---

## ✅ Hypothesis

> “A threat actor is persisting in the environment via webshells on public-facing servers, stealing credentials for lateral movement, and using encrypted traffic to hide C2 communications.”

---

## 🧱 Tactics to Focus On

1. **Initial Access** — Webshells on IIS/Apache servers
2. **Persistence** — Script-based shells in normal web directories
3. **Credential Access** — Dumping memory or stealing tokens
4. **Lateral Movement** — Remote WMI, RDP, SMB
5. **Command & Control** — Legit-looking HTTPS beacons

---

## 🔍 Hunt Steps (True Threat Hunt Chain)

---

### **1. Search for Webshell Deployment**

**Why:**
APT27 often uses **ASP, JSP, or PHP webshells** dropped in legitimate app folders (e.g., `/wwwroot`, `/htdocs`, `/inetpub`).

**Look For:**

* Sysmon Event ID 11:

  * File creation of:

    * `shell.aspx`, `1.aspx`, `web.jsp`, `update.php`
  * In paths like:

    * `C:\inetpub\wwwroot\`
    * `/var/www/html/`

**Thought Process:**

> Is a webshell hidden among legitimate app files?
> Was this dropped by a legit process or an attacker?

---

### **2. Analyze Command Execution from Web Servers**

**Why:**
Webshells often act as C2 stagers — running `cmd.exe`, `powershell.exe`, or uploading/download files.

**Look For:**

* Sysmon Event ID 1:

  * Parent process: `w3wp.exe`, `httpd.exe`, `nginx.exe`
  * Child process: `cmd.exe`, `powershell.exe`, `cscript.exe`

**Thought Process:**

> Why is the web server running shell commands?
> Was this a maintenance task or C2?

---

### **3. Trace Use of Credential Dumpers Post-Webshell**

**Why:**
APT27 has been seen dropping `mimikatz`, `Pwdump`, or using built-in APIs to grab creds.

**Look For:**

* Sysmon Event ID 10:

  * `TargetImage: lsass.exe`
  * `SourceImage: cmd.exe`, `powershell.exe`, `rundll32.exe`
* File creation: `*.dmp`, `creds.txt`, `ntds.dit`

**Thought Process:**

> Did they dump LSASS after gaining webshell access?
> Was this staged for lateral use?

---

### **4. Detect Internal Lateral Movement from Web Server**

**Why:**
APT27 has used **stolen creds + WMI/SMB** to pivot toward file servers and domain controllers.

**Look For:**

* Event ID 4624:

  * LogonType 3 (network) or 10 (RDP) from the web server
* Sysmon 3:

  * Connections from web server to internal high-value systems (AD, finance servers)

**Thought Process:**

> Is the web server a lateral staging point?
> Was there a privilege escalation or pivot attempt?

---

### **5. Inspect Suspicious HTTPS Traffic from Web Server**

**Why:**
APT27 disguises C2 traffic inside **legit-looking HTTPS beacons** — often masquerading as Microsoft services.

**Look For:**

* Sysmon Event ID 3:

  * Outbound to rare or first-seen domains over port 443
  * SNI or JA3 hashes not matching standard apps
* Beaconing behavior:

  * Small packets at regular intervals (e.g., every 60s)
  * Hosts like `outlook-secure[.]net`, `msupdate[.]live`

**Correlate With:**

* Proxy logs
* Threat intel feeds (ThreatFox, VirusTotal, PassiveTotal)

**Thought Process:**

> Is this real Microsoft traffic, or is it masquerading?
> Are we looking at encrypted C2 from a foothold?

---

### **6. Hunt for Persistence in Registry or Scheduled Tasks**

**Why:**
APT27 sometimes sets **registry run keys** or **scheduled tasks** to re-execute their C2 stagers after reboot.

**Look For:**

* Sysmon Event ID 13:

  * Registry path: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  * Value: `update`, `svchost`, `chromeupdater`

* Event ID 4698:

  * Scheduled task named like:

    * `Update Service`, `Windows Updater`, `Driver Helper`

**Thought Process:**

> Did they ensure persistence without a service or startup script?
> Are names meant to blend in with Windows processes?

---

## 🧠 Summary

APT27 doesn’t make noise. This hunt is built to **find low-signal but high-risk activity**, especially:

* Webshells dropped on live servers
* Cmd/PowerShell running under web server context
* LSASS dumps without malware
* HTTPS C2 that hides in Outlook or update traffic
* Pivoting toward internal infrastructure using valid creds
