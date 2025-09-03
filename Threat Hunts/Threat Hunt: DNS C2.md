> 🎯 **Objective**: Detect **DNS tunneling C2** (e.g., dnscat2/iodine/dns2tcp/custom) used for covert comms/exfil by spotting **weird query shapes**, **record-type abuse**, **periodic beacons**, and **NXDOMAIN-heavy patterns**—then tie them back to the **originating host/process**.

---

## ✅ Hypothesis

> “A host is beaconing over DNS to an attacker-controlled domain. Data is chunked into long/high-entropy subdomains, often via `TXT` (or `NULL/ANY`), with consistent timing and abnormal TTLs/NXDOMAIN rates.”

---

## 🧱 Tactics to Focus On

1. **C2 & Exfiltration** — High-volume DNS queries with long, random labels; base32/64 chunks in subdomains
2. **Defense Evasion** — Tunnels routed through internal resolver (client appears as resolver in egress); very low TTL; domain flux under a single SLD
3. **Discovery/Staging** — Client process initiating DNS storms without matching TCP/HTTP flows

---

## 🔍 Hunt Steps (True Threat Hunt Chain)

### **1) Volume & ratio anomalies per host**

**Why:** Tunnels produce **far more DNS** than normal.
**Look for:**

* One workstation generating **10–100×** the usual DNS volume in 1–4h
* **NXDOMAIN rate spikes** (rotten subdomains are common during tunneling)
  **Thought process:**

> Is a single client hammering DNS far beyond its peers?

---

### **2) Long / structured subdomains**

**Why:** Data is encoded into labels.
**Look for:**

* **FQDN length > 100–200 chars** or **label > 50 chars**
* Base64/base32-ish chunks in labels: `[A-Za-z0-9+/=]{20,}` or `[A-Z2-7]{20,}`
  **Thought process:**

> Legit domains almost never shove 30–60 char gibberish labels all day.

---

### **3) Abused record types**

**Why:** Tunnels favor payload-friendly types.
**Look for:**

* **TXT** bursts (answers > 200 bytes)
* **NULL/ANY** (if your infra still permits them)
  **Thought process:**

> Lots of TXT from one client to one domain = red flag.

---

### **4) Beacon regularity**

**Why:** Bots phone home on a clock.
**Look for:**

* Inter-arrival times with **low variance** (e.g., every 60 ± 5s)
* Uniform query lengths across many requests
  **Thought process:**

> Human browsing is bursty; C2 beacons are metronomes.

---

### **5) Single SLD gravity & low TTL**

**Why:** Tunnels pin to one zone they control.
**Look for:**

* **Most queries** from a host going to **one SLD** (e.g., `*.attacker.tld`)
* **TTL = 0 or 1** across answers from that SLD
  **Thought process:**

> Normal CDNs cache; tunnels force re-query.

---

### **6) Tie back to process on host**

**Why:** You need the **who**.
**Look for (host logs):**

* DNS query events (Sysmon EID 22 or DNS-Client Operational) with **Image** = non-browser/non-AV process
  **Thought process:**

> If `rundll32.exe` / odd EXE is your top DNS talker, that’s your implant.

---

### **7) Correlate follow-on**

**Why:** Real ops do something next.
**Look for:**

* Shortly after DNS storm: new SMB/HTTP egress, file writes to `%ProgramData%`/`%Temp%`, process spawns (cmd/powershell/mshta).
  **Thought process:**

> Close the loop: DNS C2 → action on objectives.

---

## 🧠 Summary

* **DNS tunnels look weird**: long/encoded labels, TXT floods, NXDOMAIN spikes, low TTL, clock-like cadence to one SLD.
* **Prove it** by tying the DNS to the **originating process** on the host, not just the resolver IP.
* If two+ of the above hit in a tight window, treat it as **active C2/exfil**.

---

# 🔎 QRadar AQL (adjust field names to your DNS DSM)

### A) Top DNS talkers (volume outliers)

```sql
SELECT sourceip, COUNT(*) AS q
FROM events
WHERE categoryname ILIKE 'DNS%'
LAST 24 HOURS
GROUP BY sourceip
ORDER BY q DESC
LIMIT 100
```

### B) NXDOMAIN spike by source

```sql
SELECT sourceip, COUNT(*) AS nxd
FROM events
WHERE categoryname ILIKE 'DNS%' AND (rcode ILIKE 'NXDOMAIN' OR rcode = '3')
LAST 24 HOURS
GROUP BY sourceip
HAVING nxd >= 200
ORDER BY nxd DESC
```

### C) Long / baseX-looking queries

```sql
SELECT starttime, sourceip, query, qtype
FROM events
WHERE categoryname ILIKE 'DNS%'
  AND ( LENGTH(query) > 100
        OR query MATCHES '(?i)[A-Za-z0-9+/=]{20,}\\.'
        OR query MATCHES '(?i)[A-Z2-7]{20,}\\.' )
LAST 24 HOURS
ORDER BY starttime DESC
```

### D) TXT-heavy to single domain (payload-friendly)

```sql
SELECT sourceip, query, COUNT(*) AS hits
FROM events
WHERE categoryname ILIKE 'DNS%' AND (qtype ILIKE 'TXT' OR qtype = '16')
LAST 24 HOURS
GROUP BY sourceip, query
HAVING hits >= 50
ORDER BY hits DESC
```

### E) Single-SLD gravity (one domain dominates a host)

> If you have a `domain`/`sld` field, use it. Otherwise group on the rightmost two labels (replace with your extractor).

```sql
SELECT sourceip, domain, COUNT(*) AS q
FROM events
WHERE categoryname ILIKE 'DNS%'
LAST 24 HOURS
GROUP BY sourceip, domain
HAVING q >= 300
ORDER BY q DESC
```

### F) Periodic beacons (crude binning by minute)

```sql
SELECT sourceip, domain, DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm') AS minute, COUNT(*) AS q
FROM events
WHERE categoryname ILIKE 'DNS%'
  AND domain IS NOT NULL
LAST 2 HOURS
GROUP BY sourceip, domain, minute
HAVING q BETWEEN 1 AND 3
ORDER BY sourceip, domain, minute
```

*(Tight, steady per-minute counts over 60–120 minutes = beacon smell.)*

---

# 🛠 Velociraptor VQL (host-side; use whichever log you have)

### 1) Sysmon DNS (Event ID 22) — long/baseX subdomains

```vql
SELECT Timestamp, Computer, EventData.QueryName AS Qname,
       EventData.QueryStatus AS Status, EventData.Image AS Proc
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx')
WHERE EventID = 22
  AND (strlen(Qname) > 100 OR Qname =~ '(?i)[A-Za-z0-9+/=]{20,}\\.|[A-Z2-7]{20,}\\.'),
ORDER BY Timestamp DESC
```

### 2) Sysmon DNS — TXT-heavy from odd processes

```vql
SELECT Timestamp, Computer, EventData.Image AS Proc, EventData.QueryName AS Qname, EventData.QueryResults AS Ans
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx')
WHERE EventID = 22
  AND (EventData.QueryName =~ '(?i)\\.(txt\\.|)$' OR EventData.QueryResults =~ '(?i)"txt"')
  AND Proc !~ '(?i)(chrome|edge|firefox|outlook|teams|onedrive)\\.exe'
ORDER BY Timestamp DESC
```

### 3) Windows DNS-Client Operational (if enabled) — noisy client & NXDOMAIN

```vql
SELECT timestamp(epoch=System.TimeCreated) AS TS, Computer,
       EventData.QueryName AS Qname, EventData.QueryType, EventData.Status AS Rcode, EventData.ProcessName AS Proc
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-DNS-Client%4Operational.evtx')
WHERE EventID IN (3006, 3016)  -- query/response
  AND (strlen(Qname) > 100 OR Rcode =~ '(?i)NXDOMAIN')
ORDER BY TS DESC
```

### 4) Per-process DNS storm (find the implant)

```vql
SELECT Proc, COUNT(*) AS Q, MIN(TS) AS First, MAX(TS) AS Last
FROM (
  SELECT timestamp(epoch=System.TimeCreated) AS TS,
         coalesce(EventData.Image, EventData.ProcessName) AS Proc
  FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx')
  WHERE EventID = 22
)
GROUP BY Proc
HAVING Q >= 1000 AND (Last - First) <= 3600
ORDER BY Q DESC
```

---

## Tuning & Reality Checks

* **Resolvers vs clients:** If logs show only the **resolver** as source, pivot to **host logs (Sysmon 22 / DNS-Client)** to find the real origin.
* **CDNs can be chatty** but won’t spew **long random labels** or **TXT megabursts** with **NXDOMAIN floods**.
* **Low TTL** is supportive, not definitive—some legit services use small TTLs; the combo is what convicts.
