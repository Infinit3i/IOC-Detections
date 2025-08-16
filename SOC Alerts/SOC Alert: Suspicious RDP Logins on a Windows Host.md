## ✅ Flow of Investigation

1. ✅ Initial Access — **Logon events**
2. 🔎 Identity & Origin — **IP checks**
3. 🔐 Privilege Escalation — **4672 events**
4. ⚙️ Execution — **4688 + command line args**
5. 🔄 Lateral Movement — **4648, 4624 type 3**
6. 🪝 Persistence — **Registry, tasks, services**
7. 💾 Dropped Files — **Sysmon 11 + hash analysis**
8. 🌐 C2 / Network — **Sysmon 3, Suricata/Zeek**
9. 🧠 Big Picture — **Cross-host correlation**

---

### **1. Spot Unusual Logons**

**Trigger:**
Look for **Event ID 4624** (Successful Logon) with `LogonType=10` (RemoteInteractive, i.e., RDP).

**Why this matters:**

* `LogonType 10` = Remote Desktop.
* If seen outside of maintenance windows or involving non-admin accounts, this can be a red flag.
* Initial access or lateral movement via RDP is common in hands-on-keyboard attacks.

**Thought Process:**

> Why is RDP being used at this time?
> Is this user supposed to RDP?
> Is this from a known IP?

---

### **2. Map IPs to Geolocation and Known Ranges**

**Action:**
Pull `Source IP` from the 4624 event and enrich it:

* GeoIP lookup
* Check against VPNs, TOR nodes, public IP reputation feeds

**Why:**

* Suspicious logins from external or rare internal IPs are high signal.
* RDP exposed to the internet is **instant trouble**.

**Thought Process:**

> Was the login from outside the corporate VPN?
> Was it an anomalous country?
> First time seen?

---

### **3. Look for Event ID 4672 (Special Privileges Assigned)**

**Action:**
Check if the same account received elevated privileges.

**Why:**

* Event 4672 often follows a successful login by privileged accounts.
* It shows **Administrative privileges** being assigned (e.g., SeDebugPrivilege, SeTcbPrivilege).

**Thought Process:**

> Did the attacker just get admin access?
> Was this escalation part of the login session?

---

### **4. Check for Process Creation Events — 4688 (or Sysmon 1)**

**Action:**
Find processes spawned by the account or after the login time.

**Look for:**

* `cmd.exe`, `powershell.exe`, `wscript.exe`, `rundll32.exe`
* Suspicious command lines (`DownloadString`, `IEX`, base64, etc.)

**Why:**

* This shows what the user did after logging in.
* Attackers often run recon or payloads after gaining access.

**Thought Process:**

> What’s their next move?
> Did they drop a RAT? Beacon?

---

### **5. Look for Lateral Movement**

**Action:**
Check for Event IDs:

* **4648**: Logon with explicit credentials
* **4624** + LogonType 3: Network logon
* **4776**: NTLM authentication

**Why:**

* These show if the threat is pivoting inside the network.
* Reuse of credentials between hosts = lateral movement.

**Thought Process:**

> Are they exploring the network?
> Where are they going next?
> Are they using the same account to move?

---

### **6. Check for Registry Changes or Persistence**

**Action:**
Look for:

* Event ID 4657 (Registry value changes)
* Sysmon Event ID 13 (Registry key modifications)

**Why:**

* Persistence mechanisms often modify `Run` keys, services, or WMI.

**Thought Process:**

> Are they setting up persistence?
> Did a service or script change after login?

---

### **7. Review Scheduled Tasks or Service Creation**

**Action:**
Check for:

* **Event ID 4698**: Scheduled Task created
* **Event ID 7045**: New service installed

**Why:**

* These are favorite persistence mechanisms post-RDP.

**Thought Process:**

> Did they create something that will auto-run?
> Was a malicious binary installed as a service?

---

### **8. Pull File Write Events and Hashes**

**Action:**
Check:

* Sysmon Event ID 11 (FileCreate)
* Pull SHA256 hashes for any suspicious executables

**Why:**

* See what binaries were dropped.
* Hashes can be used to check threat intel feeds or sandbox.

**Thought Process:**

> What files were dropped right after login?
> Do these match known malware?

---

### **9. Check Outbound Network Connections**

**Action:**
Use Sysmon Event ID 3 or network sensor logs (e.g., Zeek, Suricata):

* Domains/IPs accessed
* Ports/protocols used

**Why:**

* Many tools beacon out or exfiltrate data after access.
* RDP abuse often includes C2 setup.

**Thought Process:**

> Are they talking to C2 infrastructure?
> Are we seeing lateral SMB, LDAP, or other movement?

---

### **10. Correlate with Other Hosts**

**Action:**
Pivot:

* Did this user or IP show up elsewhere?
* Are similar patterns occurring on peer systems?

**Why:**

* Threat actors don’t stop at one machine.
* This gives a bigger picture and scope of compromise.

**Thought Process:**

> Is this a one-off or part of a campaign?
> Was a shared account compromised across systems?
