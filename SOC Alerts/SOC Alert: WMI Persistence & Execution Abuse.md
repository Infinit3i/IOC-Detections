## ✅ Flow of Investigation

1. 🧠 Behavioral Trigger — **Suspicious WMI activity or persistence alert**
2. 🪪 Identify WMI Consumers/Filters/Bindings
3. 🧬 Inspect Embedded Commands (Scripts, Binaries, Arguments)
4. 🕵️ Map Creation Events — Who created the WMI objects?
5. 🔐 Privilege Level and Context
6. ⚙️ Process Spawn Behavior — Sysmon 1
7. 🛰 Network or Lateral Indicators
8. 💾 Dropped Artifacts & Registry Links
9. 🔄 Cross-Host WMI Scanning
10. 🧹 Contain, Remove, and Harden

---

### **1. Behavioral Trigger — WMI Event or EDR Flag**

**Trigger:**

* Detection by EDR (e.g., “WMI Consumer Creation” or “Suspicious Persistence via WMI”)
* Behavioral anomaly: PowerShell spawning from `WmiPrvSE.exe` or `EventConsumer`

**Why this matters:**

* WMI is often used **without touching disk**, and persistence via event subscriptions is **fileless**.

**Thought Process:**

> Is this WMI execution, persistence, or both?
> Was the behavior new or rare on this host?

---

### **2. Identify WMI Consumers/Filters/Bindings**

**Action:**
Use WMI command-line tools or PowerShell to enumerate:

```powershell
# List all active WMI persistence objects
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

**Why:**

* This reveals if a task is being triggered based on system events (boot, login, etc).
* Look for `CommandLineEventConsumer`, `ActiveScriptEventConsumer`, etc.

**Thought Process:**

> What kind of WMI consumer is registered?
> When does it trigger? Boot? Logon?

---

### **3. Inspect Embedded Commands**

**Action:**
Extract and analyze:

* PowerShell scripts
* EXE/DLL paths
* VBScript
* Encoded payloads

**Why:**

* The payload might:

  * Execute malware
  * Open backdoors
  * Run recon tasks

**Thought Process:**

> Is this a malicious payload or a legit script?
> Where does it point — local or remote?

---

### **4. Map Creation Events**

**Action:**
Use Event IDs:

* **Sysmon 1** (if attacker used `wmic.exe` or `powershell`)
* **Event ID 5861 / 5860** (WMI object creation, if logging is enabled)
* Registry timestamps and Prefetch for execution artifacts

**Why:**

* Mapping back to the **creator process/user** helps identify the **entry point**.

**Thought Process:**

> Was WMI used after a logon?
> Which user and tool created the persistence?

---

### **5. Privilege Level and Context**

**Action:**
Check:

* Did the attacker have local admin or SYSTEM?
* Was a token stolen?

**Why:**

* WMI persistence typically requires elevated permissions.
* Helps assess **blast radius** and **threat maturity**.

**Thought Process:**

> Did they escalate or already have privileges?
> Are they targeting long-term stealth?

---

### **6. Process Spawn Behavior**

**Action:**
Look for:

* `WmiPrvSE.exe` spawning `cmd.exe`, `powershell.exe`, etc.
* Event ID:

  * Sysmon 1 (Process Creation)
  * Sysmon 10 (Injection / Access to other processes)

**Why:**

* WMI consumers may **launch payloads** when triggered.

**Thought Process:**

> What does WMI ultimately execute?
> Is it downloading, pivoting, or data staging?

---

### **7. Network or Lateral Indicators**

**Action:**
Check:

* Sysmon 3 (network connection)
* Suricata/Zeek (external IPs, DNS, HTTP)
* SMB, WMI, RPC calls to other hosts

**Why:**

* Many WMI-based infections act as **C2 droppers** or spread laterally via WMI itself.

**Thought Process:**

> Are they using WMI to move laterally?
> Do we see pivoting via remote WMI execution?

---

### **8. Dropped Artifacts & Registry Links**

**Action:**
Check:

* File writes around the time of WMI object creation (Sysmon 11)
* Registry modifications (Sysmon 13)
* Autorun locations (`Run`, `RunOnce`, services)

**Why:**

* WMI persistence might **call external payloads** stored locally.

**Thought Process:**

> Did they drop files before setting WMI?
> Is WMI calling something still on disk?

---

### **9. Cross-Host WMI Scanning**

**Action:**
Use PowerShell or EDR queries to enumerate WMI persistence on other hosts:

```powershell
Invoke-WmiMethod -Namespace root\subscription -Class __EventFilter
```

Or tools like:

* [WMI Explorer](https://github.com/vinaypamnani/wmie2)
* [WMI Persistence Finder](https://github.com/Neo23x0/WMIHunt)

**Why:**

* Detects repeat usage or coordinated deployment.

**Thought Process:**

> Is this persistence technique replicated on multiple systems?
> Was it part of an implant or RAT?

---

### **10. Contain, Remove, and Harden**

**Action:**

* Delete WMI persistence:

```powershell
# Example: Remove a suspicious event consumer
$consumer = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object {$_.Name -eq "EvilTask"}
$consumer.Delete()
```

* Dump full WMI repository for forensic review
* Harden via:

  * Enabling WMI logging
  * Blocking remote WMI (unless needed)
  * Disabling unused namespaces

**Why:**

* WMI persistence can be **hard to spot again later** if not fully removed.

**Thought Process:**

> Can we surgically clean without collateral damage?
> How do we prevent reimplantation?
