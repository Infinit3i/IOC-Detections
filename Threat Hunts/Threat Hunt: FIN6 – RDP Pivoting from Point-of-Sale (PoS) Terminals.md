
> 🎯 **Objective**: Identify lateral movement originating from PoS terminals via **RDP**, enabling FIN6 to access payment processing infrastructure or exfiltrate cardholder data.

FIN6 has historically exploited PoS systems, using them as **stealthy launch points** for broader access — **abusing valid credentials and RDP**, rather than deploying malware immediately.

---

## ✅ Hypothesis

> “A threat actor is using PoS terminals as a pivot point via RDP to access internal financial infrastructure using stolen or reused credentials.”

---

## 🧱 Tactics to Focus On

1. **Initial Access** — PoS compromise via malware or creds
2. **Execution** — RDP sessions to other internal systems
3. **Credential Access** — Reuse or theft of domain creds
4. **Lateral Movement** — Pivoting toward financial servers
5. **Collection** — Memory scraping or filesystem access
6. **Exfil Preparation** — Data staging or compression

---

## 🔍 Hunt Steps (True Threat Hunt Chain)

---

### **1. Identify PoS Terminal Logon Behavior**

**Why:**
PoS systems usually have **limited, repetitive behavior** — sudden RDP logons or outbound connections are suspicious.

**Look For:**

* Event ID 4624 (Logon Success):

  * From PoS IPs/hostnames
  * `LogonType=10` (RDP) **to internal systems**
* Sysmon 3 or firewall logs:

  * `DestinationPort: 3389` from PoS devices

**Thought Process:**

> Why is this PoS terminal initiating RDP?
> What account is being used?

---

### **2. Detect First-Time RDP Usage from PoS Systems**

**Why:**
PoS systems shouldn't normally initiate RDP — any occurrence may be an IOC.

**Look For:**

* First-seen connections to:

  * Financial servers
  * Domain controllers
* RDP use outside of known maintenance windows

**Correlate With:**

* Host inventory to confirm PoS designation
* Network segmentation policy

**Thought Process:**

> Is this PoS terminal breaking out of its VLAN or subnet?
> Who authorized this connection?

---

### **3. Look for Lateral RDP Spread Using Same Account**

**Why:**
FIN6 often reuses valid domain or local creds to move laterally after gaining access.

**Look For:**

* Event ID 4648 (Explicit credential use)
* Same account used from multiple systems in short succession
* Event ID 4624:

  * Multiple `LogonType=10` from different PoS boxes

**Thought Process:**

> Is this account bouncing across systems?
> Was it stolen from another compromised PoS system?

---

### **4. Trace File Access or Tool Execution After RDP**

**Why:**
Once inside financial systems, FIN6 looks for card data or database access.

**Look For:**

* Sysmon Event ID 1:

  * `powershell.exe`, `cmd.exe`, `certutil.exe`, `rar.exe`
* Sysmon Event ID 11:

  * Files copied to `%TEMP%`, `%APPDATA%`, `C:\ProgramData\`
* Recon commands:

  * `dir`, `ipconfig`, `netstat`, `whoami`, etc.

**Thought Process:**

> Is this initial recon?
> Were scripts or tools dropped from the PoS box?

---

### **5. Detect Memory Scraping or Sensitive File Collection**

**Why:**
FIN6 may use custom or open-source tools to scrape memory for PANs (Primary Account Numbers).

**Look For:**

* Executables named:

  * `memscraper.exe`, `posdump.exe`, `grabber.dll`, `scrape.ps1`
* Event ID 10:

  * Process access to `explorer.exe`, `pos.exe`, or browser processes

**Thought Process:**

> Was card data harvested?
> Did they extract browser cache, keystrokes, or memory?

---

### **6. Search for Exfil Prep via Compression or Staging**

**Why:**
FIN6 has compressed scraped data before uploading via FTP, HTTP, or C2.

**Look For:**

* File creation:

  * `.zip`, `.rar`, `.cab`, `.7z`
* Use of:

  * `makecab.exe`, `powershell Compress-Archive`, or 3rd party tools
* Files written to:

  * `C:\ProgramData`, `%TEMP%`, or shared drives

**Thought Process:**

> What was staged and where?
> Are these archives of scraped cardholder data?

---

### **7. Identify Potential C2 or Exfil Paths**

**Why:**
Exfil typically happens after data collection is complete.

**Look For:**

* Sysmon Event ID 3:

  * Long-lived outbound sessions from finance servers or PoS boxes
  * FTP/HTTP POSTs or DNS tunneling

**Correlate With:**

* Proxy logs
* Known C2 IPs/domains (via ThreatFox, AbuseIPDB)

**Thought Process:**

> Where did the data go?
> Did this PoS box become an exfil proxy?

---

## 🧠 Summary

This hunt tracks **FIN6-style pivoting** from low-privileged PoS boxes into sensitive environments:

* Unusual RDP behavior from fixed-function terminals
* Credential reuse across systems
* Card data harvesting via memory scraping
* Staging + potential exfil over normal ports
