
> 🎯 **Objective**: Hunt for stealthy, post-compromise activity that aligns with **APT29** tradecraft — particularly **WMI-based lateral movement** and **credential access** without malware.

This is a true **assumption-based hunt** with no alerts to guide you. The idea is to **form hypotheses**, pull logs, and **test each stage** of behavior expected from a sophisticated actor.

---

## ✅ Hypothesis

> “A threat actor is using WMI and built-in Windows tools (LOLBINs) to move laterally and extract credentials, avoiding direct use of malware.”

---

## 🧱 Tactics to Focus On

1. **Execution** — WMI, PowerShell, Rundll32, etc.
2. **Credential Access** — LSASS abuse, token theft, DPAPI
3. **Lateral Movement** — WMI, SMB, Remote Services
4. **Defense Evasion** — Clearing logs, timestomping, LOLBIN abuse
5. **Persistence** — WMI Event Consumers, Registry, Scheduled Tasks

---

## 🔍 Hunt Steps (True Threat Hunt Chain)

---

### **1. Hunt for Unusual WMI Usage**

**Why:**
APT29 has used WMI for both persistence and remote code execution without dropping files.

**Look For:**

* Sysmon Event ID 1:

  * `powershell.exe` or `wmic.exe` as child of `explorer.exe` or `svchost.exe`
* Execution of:

  ```powershell
  Invoke-WmiMethod
  Get-WmiObject
  Win32_Process.Create
  ```

**Thought Process:**

> Why is PowerShell using WMI to launch a process?
> Who ran `wmic.exe` manually?

---

### **2. Hunt for Remote WMI Execution**

**Why:**
WMI is often used for stealthy lateral movement without touching disk.

**Look For:**

* `Event ID 4688` + `wmic.exe` or `powershell.exe` with remote hostname
* Sysmon Event ID 3 showing RPC to port 135, 445, 5985

**Command Examples:**

```cmd
wmic /node:HOSTNAME process call create "cmd.exe /c whoami"
```

**Thought Process:**

> Who used remote WMI in the org?
> Is this behavior normal for this user/system?

---

### **3. Look for LSASS Access Without AV Trigger**

**Why:**
APT29 uses stealthy methods like `rundll32 comsvcs.dll`, P/Invoke, or `Out-Minidump` in PowerShell.

**Look For:**

* Sysmon Event ID 10:

  * `TargetImage: lsass.exe`
  * `GrantedAccess: 0x1010`, `0x1438`, `0x1fffff`
* No alert from EDR = likely obfuscated or renamed tools

**Thought Process:**

> Who accessed LSASS without malware?
> Any file created that could be a dump?

---

### **4. Hunt for Dump File Creation**

**Why:**
APT29 often exfiltrates credentials by creating memory dumps then zipping them.

**Look For:**

* Sysmon Event ID 11:

  * Files like `*.dmp`, `*.zip`, `*.7z`, or renamed executables
  * Unusual paths like `C:\ProgramData\temp\` or `%AppData%`

**Thought Process:**

> Are these files benign or staging dumps?
> Was compression used to prep for exfil?

---

### **5. Look for Abnormal Logon Patterns**

**Why:**
Credential theft is followed by use of new accounts or logons from new devices.

**Look For:**

* Event ID 4624 + LogonType 3 (network) or 10 (RDP)
* Event ID 4648 (explicit credentials used)
* Logons from unusual hosts/users at odd hours

**Thought Process:**

> Did we see this user log in from a new device?
> Are they jumping from host to host?

---

### **6. Hunt for WMI Persistence Objects**

**Why:**
APT29 has used `__EventFilter` and `CommandLineEventConsumer` objects to persist without files or tasks.

**Look For:**

* Query:

  ```powershell
  Get-WmiObject -Namespace root\subscription -Class __EventConsumer
  Get-WmiObject -Namespace root\subscription -Class __EventFilter
  ```
* Check for odd triggers like:

  * EventType = logon
  * CommandLine = PowerShell with base64 or Invoke-Expression

**Thought Process:**

> Is this event consumer legitimate?
> When did it get created? Who authored it?

---

### **7. Check for Network Connections to Rare Hosts**

**Why:**
APT29 sets up **low-volume, long-dwell C2 channels**.

**Look For:**

* Sysmon Event ID 3:

  * Long-lived or rare outbound connections
  * Domains without reverse DNS
  * Small beacon packets over HTTP/DNS

**Correlate With:**

* Zeek logs (if available)
* GreyNoise, VirusTotal, AbuseIPDB

**Thought Process:**

> Is this beaconing to a rare or first-seen IP?
> Does it match normal app behavior?

---

### **8. Correlate Account Use Across Multiple Hosts**

**Why:**
Dumped creds get reused on critical servers.

**Look For:**

* Lateral movement: RDP, SMB, WMI, PS Remoting
* Same user logging into >2 machines in short time

**Thought Process:**

> Is this normal admin behavior?
> Or did a threat actor reuse creds?

---

## 🧠 Summary

This was a **non-alert-driven hunt** that required:

* Understanding of **APT29 behaviors**
* Focused hypothesis: stealthy, fileless, lateral
* Chaining WMI + LSASS + logons + file writes + beacons
