## ✅ Flow of Investigation

1. 🧠 Behavioral Trigger — **EDR or AV alerts on memory access**
2. 🔍 Look for Suspicious Tools and Commands
3. 👣 Identify Process Access Patterns (Sysmon 10)
4. 🧬 Check for Known LSASS Dump Methods
5. 🔐 Map the User and Privilege Context
6. 💾 Identify Dump Destination (File creation or exfil)
7. 📡 Look for Credential Use or Lateral Movement
8. 🧯 Investigate Defense Evasion Techniques
9. 🔄 Cross-host Credential Use
10. ⚔️ Contain, Reimage, and Rotate Credentials

---

### **1. Behavioral Trigger — LSASS Alert or Memory Access**

**Trigger:**

* AV/EDR alert: "Mimikatz", "Procdump on LSASS", or "Unauthorized memory read"
* Defender alert: **"Suspicious credential theft"**
* Sysmon Event 10 on `lsass.exe`

**Why this matters:**

* If someone touched `lsass.exe`, they're either doing debugging or credential theft — and you can assume it's malicious until proven otherwise.

**Thought Process:**

> Is this legitimate?
> Why was `lsass.exe` touched outside of normal usage?

---

### **2. Look for Suspicious Tools and Commands**

**Action:**
Search logs and EDR telemetry for:

* `procdump.exe -ma lsass.exe`
* `taskmgr.exe`, `rundll32`, `comsvcs.dll`
* `ProcessHacker.exe`, `mimikatz`, `nanodump`, `dumpert`
* PowerShell using `Out-Minidump` or P/Invoke techniques

**Why:**

* Many tools are reused across attackers. Command line flags give it away.

**Thought Process:**

> What tool was used?
> Did they rename it? Side-load it?

---

### **3. Identify Process Access Patterns (Sysmon 10)**

**Action:**
Check Sysmon Event ID **10**:

* `SourceImage`: Suspicious binary (e.g., `procdump.exe`)
* `TargetImage`: `lsass.exe`
* `GrantedAccess`: `0x1010`, `0x1fffff`, `0x1438`, etc

**Why:**

* These values indicate **read/process access** used in LSASS dumping.

**Thought Process:**

> Did this tool access `lsass.exe` directly?
> Was this post-exploitation or initial compromise?

---

### **4. Check for Known LSASS Dumping Techniques**

**Action:**
Correlate behavior with known techniques:

* **ProcDump**: `-ma lsass.exe`
* **MiniDumpWriteDump API**
* **comsvcs.dll** abuse:

  ```cmd
  rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump <PID>
  ```
* **Powershell reflection**: `Invoke-Mimikatz`, `Out-Minidump`
* **Direct memory reading**: using `NtReadVirtualMemory`

**Why:**

* Identifying the method used helps track the attack sophistication and timeline.

**Thought Process:**

> Which technique was used and why?
> Are they staying stealthy?

---

### **5. Map the User and Privilege Context**

**Action:**

* Link access attempts to specific logins (Event ID 4624)
* Look for `LogonType=2` (console), `10` (RDP), or `11` (cached domain)
* Check for **4672** (Special privileges assigned)

**Why:**

* LSASS access requires **SeDebugPrivilege** or **SYSTEM** — attacker must escalate.

**Thought Process:**

> Did they use a stolen account to access LSASS?
> Was this SYSTEM-level? Token theft?

---

### **6. Identify Dump Destination**

**Action:**
Look for:

* Sysmon Event ID **11** (FileCreate)
* Dumped files like `lsass.dmp`, `*.dmp`, `*.tmp`, or obfuscated files

**Why:**

* You must find and secure the dump file before it’s exfiltrated.

**Thought Process:**

> Where was the dump stored?
> Was it cleaned up afterward?

---

### **7. Look for Credential Use or Lateral Movement**

**Action:**

* Check for:

  * **4648** (Explicit credentials used)
  * **4624** (New logons from stolen accounts)
  * RDP or SMB sessions after dump time
* Use EDR to trace session tokens

**Why:**

* Attackers dump LSASS to **move laterally** or access **privileged systems**.

**Thought Process:**

> Did they pivot after stealing creds?
> What accounts were reused?

---

### **8. Investigate Defense Evasion Techniques**

**Action:**
Check for:

* Tampering with Defender (Event ID 5007, registry edits)
* Disabling ETW or AMSI
* Disabling Credential Guard
* DLL sideloading to mask dumping

**Why:**

* Skilled actors often disable security tools or evade detection when dumping LSASS.

**Thought Process:**

> Were security tools bypassed before or after the dump?
> Did we miss the actual dump execution?

---

### **9. Cross-host Credential Use**

**Action:**
Hunt for same credentials on other systems:

* Kerberos tickets
* NTLM logons
* Same session tokens

**Why:**

* Lateral movement and privilege escalation across endpoints is often tied to one dump.

**Thought Process:**

> Was this a one-off or are we in an active campaign?
> Are domain admin creds exposed?

---

### **10. Contain, Reimage, and Rotate Credentials**

**Action:**

* Rotate all affected user and service account credentials
* Reimage any system where LSASS was accessed
* Monitor for re-use attempts or beaconing

**Why:**

* Once credentials are stolen, **no remediation is complete without rotation.**

**Thought Process:**

> How do we contain without alerting the attacker?
> Do we have a full list of affected credentials?
