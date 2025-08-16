## ✅ Flow of Investigation

1. 🧠 Behavioral Trigger — **New or unusual scheduled task**
2. 🕵️ Initial Detection — **Windows Event ID 4698 or Sysmon 1**
3. 🧱 Validate Task Content — **Command line and arguments**
4. 👤 Identify Creating Account — **Correlate with Event 4624**
5. 🔐 Privilege Context — **Was it created as SYSTEM or via escalation?**
6. 🧬 Trace Task Payload — **Binary hash and origin**
7. 📡 Observe Network Behavior — **Sysmon 3 or proxy logs**
8. 🪝 Confirm Persistence Behavior — **Reboots, autoruns, services**
9. 🔄 Pivot Across Hosts — **Repeat task across endpoints?**
10. ⚔️ Isolate, Detonate, Contain

---

### **1. Behavioral Trigger — Suspicious Task Creation**

**Trigger:**

* Alert from EDR or log source (e.g., unexpected use of `schtasks.exe`)
* `4698` Event ID (Task creation)
* Sysmon 1 showing suspicious `schtasks.exe` or `AT.exe` usage

**Why this matters:**

* Attackers use scheduled tasks for persistence, delayed execution, or lateral staging.
* It's a native binary and often trusted.

**Thought Process:**

> Why is this task being created?
> Is it expected behavior for this user/system?

---

### **2. Initial Detection — Event ID 4698 or Sysmon Process**

**Action:**

* Collect metadata:

  * `TaskName`
  * `Author`
  * `Command`
  * `Trigger type` (Time? Boot? Login?)
* In Sysmon, check for:

  * `ParentImage` and `CommandLine` with `schtasks.exe` or `AT.exe`

**Why:**

* Provides visibility into task creation.
* Command line often reveals intent.

**Thought Process:**

> Was this a manually created task?
> What exactly will this task execute?

---

### **3. Validate Task Content**

**Action:**

* Analyze command in task: Powershell, .bat, .exe?
* Decode base64, check obfuscation, downloaders, LOLBINs

**Why:**

* Payload content often contains recon, downloaders, or persistence logic.

**Thought Process:**

> Is this a malicious command or just a sysadmin action?
> Any remote connections or encoded payloads?

---

### **4. Identify Creating Account**

**Action:**

* Correlate timestamp with `4624` (Successful Logon)
* Identify `TargetUserName`, `LogonType`, and `SourceIP`

**Why:**

* Determines if task was created by:

  * Legitimate user
  * Compromised account
  * SYSTEM or service account

**Thought Process:**

> Was this done by an admin or a compromised standard user?
> Was this done via RDP, PS Remoting, etc?

---

### **5. Privilege Context**

**Action:**

* Was the user a local admin or did privilege escalation occur?
* Check:

  * `4672` (Special privileges)
  * Sysmon 10 (Access to LSASS)
  * Execution from `explorer.exe` vs `services.exe`

**Why:**

* If privilege elevation occurred before task creation, it's high risk.

**Thought Process:**

> Did they escalate to SYSTEM to persist?
> Was the task created using stolen tokens or elevated shell?

---

### **6. Trace Task Payload**

**Action:**

* Check file creation near task creation (Sysmon 11)
* Extract binary/scripts dropped
* Hash and analyze via:

  * VirusTotal
  * HybridAnalysis
  * UnpacMe

**Why:**

* Ties scheduled task to actual malicious payloads.

**Thought Process:**

> What does the task run?
> Is it an info stealer, beacon, or ransomware loader?

---

### **7. Observe Network Behavior**

**Action:**

* Review Sysmon 3 (outbound connections)
* Correlate timing with task execution trigger
* Look for DNS tunneling, HTTP/S callbacks, etc.

**Why:**

* Many scheduled tasks are just initial loaders for C2 connections.

**Thought Process:**

> Where is the task phoning home to?
> Any exfiltration behavior?

---

### **8. Confirm Persistence Behavior**

**Action:**

* Check:

  * Reboot and auto-execute triggers
  * Registry: `Run`, `RunOnce`, `Services`
  * Scheduled task XML files (`%SystemRoot%\System32\Tasks\`)

**Why:**

* Scheduled tasks are resilient and survive reboots.
* May be hidden (non-visible, system-only tasks).

**Thought Process:**

> Is this a one-shot or long-term foothold?
> Was the task designed to come back?

---

### **9. Pivot Across Hosts**

**Action:**

* Hunt for similar task names or hashes on other endpoints
* Use EDR or log aggregation to scan:

  * Sysmon 1: `schtasks.exe`
  * Event ID 4698 + `CommandLine`

**Why:**

* APTs and malware families reuse task names, techniques.

**Thought Process:**

> Is this a targeted host or a broader intrusion?
> Any patterns across the fleet?

---

### **10. Isolate, Detonate, Contain**

**Action:**

* Isolate host
* Submit binaries to sandbox
* Export scheduled task via `schtasks /query /xml`
* Remove task and remediate persistence

**Why:**

* Ends attacker foothold
* Provides forensic evidence for IR and threat intelligence

**Thought Process:**

> How do we surgically contain without tipping off the threat actor?
> What IR follow-up is required?
