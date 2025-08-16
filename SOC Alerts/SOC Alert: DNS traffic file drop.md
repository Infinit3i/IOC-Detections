## ✅ Flow of Investigation

1. 🧠 Behavioral Trigger — **Odd DNS traffic or alerts**
2. 🔍 Identify the Source Host — **Asset & user context**
3. 📈 Analyze DNS Patterns — **Frequency, length, entropy**
4. 🛠 Inspect Process Behavior — **Sysmon 1, 15**
5. 📡 Check for Network Indicators — **Sysmon 3, Zeek, Suricata**
6. 📂 Review File Drops — **Sysmon 11**
7. 🔄 Detect Persistence — **Registry, Tasks, WMI**
8. 🔐 Privilege Context — **4624, 4672, Token abuse**
9. 🕸 Expand Hunt to Peer Hosts
10. ⚔️ Confirm and Contain

---

### **1. Behavioral Trigger — Suspicious DNS Tunneling Patterns**

**Trigger:**
Detect an anomaly via:

* IDS (e.g., Suricata DNS tunneling signatures)
* Long/random subdomain requests (e.g., `abnsdj23ndjsd.domain.com`)
* Excessive DNS queries

**Why this matters:**

* C2 channels often use DNS to bypass firewalls and exfil data.
* Long and frequent DNS queries can encode data payloads or commands.

**Thought Process:**

> Why is this host generating thousands of DNS requests?
> Are the domains new, suspicious, or random?

---

### **2. Identify the Source Host**

**Action:**
Correlate the DNS alerts to the actual internal host:

* Pull hostname, MAC, IP
* Look up the user logged in (Event 4624)

**Why:**

* Gives context — is this a dev machine, admin system, kiosk?
* You need to scope initial impact.

**Thought Process:**

> Who owns this box?
> Does their role justify unusual DNS patterns?

---

### **3. Analyze DNS Patterns**

**Action:**

* Use Zeek DNS logs or Suricata + Sysmon Event ID 22
* Focus on:

  * Query length
  * Frequency
  * TTL values
  * Uncommon TLDs (e.g., `.xyz`, `.tk`)
  * Unresolved lookups

**Why:**

* DNS exfil often looks like this:
  `ABCD1234.attacker.com` every 2 seconds, 2000 times

**Thought Process:**

> Does this look like encoded data?
> Are they using DNS as transport?

---

### **4. Inspect Process Behavior (Sysmon 1 & 15)**

**Action:**
Look for processes that triggered DNS queries:

* `powershell.exe`, `python.exe`, `nslookup.exe`, custom binaries
* Track parent-child relationships
* Check command-line arguments (Sysmon 1)
* Look for image loads (Sysmon 7) and module loads (Sysmon 6/10)

**Why:**

* Malware may inject into legitimate processes or spawn its own C2 binary.
* You can tie network behavior to execution flow.

**Thought Process:**

> What process was making those DNS calls?
> Was it a known app or custom executable?

---

### **5. Check for Network Indicators**

**Action:**
Use:

* Sysmon 3 (network connections)
* Suricata/Zeek for protocol-level logs

**Why:**

* DNS isn't the only traffic — maybe it also reached out over HTTP/S or ICMP.
* Might pivot to full C2 over a different protocol.

**Thought Process:**

> Is there fallback traffic?
> Are we only seeing the tip of the comms?

---

### **6. Review File Drops**

**Action:**
Check:

* Sysmon 11 (file creation)
* Look for dropped .exe/.dll/.ps1 payloads near the DNS beaconing time

**Why:**

* Many DNS loaders drop secondary payloads
* Binary hashes can be matched to known malware

**Thought Process:**

> What was delivered?
> Can we get the hash and submit to VT/sandbox?

---

### **7. Detect Persistence Mechanisms**

**Action:**
Review:

* Sysmon 13: Registry modifications
* Sysmon 19/20: WMI subscriptions
* Event ID 4698: Task creation

**Why:**

* If malware survives reboot, you'll find persistence.
* DNS C2 often pairs with registry or scheduled tasks to maintain access.

**Thought Process:**

> Are they ensuring they come back later?
> Did they plant a hidden scheduled task?

---

### **8. Privilege Context**

**Action:**
Check:

* 4624: Logons (was an admin involved?)
* 4672: Special privileges
* 4673/4674: Sensitive privilege use
* Sysmon 10: Process access (token stealing, injection)

**Why:**

* Even if DNS C2 was user-level, they may escalate.
* Look for token impersonation, LSASS access, UAC bypasses.

**Thought Process:**

> Did they elevate from user to SYSTEM?
> Are they staging for lateral movement?

---

### **9. Expand Hunt to Peer Hosts**

**Action:**
Pivot:

* Same user on other systems
* Same C2 domain queried by others
* Same dropped file hash

**Why:**

* If it’s part of a campaign, more systems are likely involved.
* Helps you define the blast radius.

**Thought Process:**

> Is this isolated or part of a larger breach?
> Should we start containment across the org?

---

### **10. Confirm and Contain**

**Action:**

* Trigger endpoint isolation
* Collect volatile artifacts
* Send binaries to sandbox
* Disable accounts, block domains

**Why:**

* Response must follow evidence.
* Always assume you're late — act fast and document everything.

**Thought Process:**

> Can we contain before it spreads further?
> Do we have enough artifacts for full IR?
