
> 🎯 **Objective**: Catch **Kerberoasting** (TGS requests for SPN accounts → offline crack) and **AS-REP roasting** (TGT without preauth for `DONT_REQ_PREAUTH` users → offline crack) **before** creds are reused for lateral movement.

---

## ✅ Hypothesis

> “An attacker enumerated SPNs/AS-REP-able users, pulled crackable Kerberos tickets (RC4/weak), then used recovered passwords to log on across hosts.”

---

## 🧱 Tactics to Focus On

1. **Collection** — Burst of TGS (4769) across many SPNs, RC4 tickets (0x17).
2. **Account Manipulation** — Flip `DONT_REQ_PREAUTH` on a user (4738).
3. **AS-REP Roast** — 4768 *success* without preauth; 4771 *fail* bursts during scouting.
4. **Tooling** — `Rubeus`, `setspn`, `adfind`, Impacket `GetUserSPNs.py`.
5. **Follow-on** — New 4624 logons from cracked accounts, lateral spray.

---

## 🔍 Hunt Steps (True Threat Hunt Chain)

### 1) Flag RC4 Kerberoast patterns

**Why:** Roasters prefer RC4 tickets; AES is harder to crack.
**Look For:** **4769** with `TicketEncryptionType=0x17` from a **workstation** or a single user hitting **many unique SPNs** in minutes.
**Thought:** Is this normal app auth, or a one-off host/user fanning out?

### 2) High-cardinality SPN pulls from one source

**Why:** Enumeration + mass TGS requests precede cracking.
**Look For:** Same client (IP/host/user) requesting **10+ distinct SPNs** in <15 min.
**Thought:** Legit app clients don’t sweep random SPNs.

### 3) AS-REP roast successes

**Why:** Accounts with **Do not require preauth** hand back crackable AS-REPs.
**Look For:** **4768** (TGT requested) **success** where **Pre-Authentication Type is empty/0** for a **user** (not computer).
**Thought:** That user is roastable—why?

### 4) AS-REP scouting (failures)

**Why:** Attackers probe many users to find roastable ones.
**Look For:** **4771** bursts from one IP with **Failure Code 0x18** (preauth required).
**Thought:** One source sweeping many users = reconnaissance.

### 5) Account control flips enabling roast

**Why:** Post-compromise, they set `DONT_REQ_PREAUTH` to enable AS-REP.
**Look For:** **4738** (user changed) where **UserAccountControl** adds *Does not require Kerberos preauthentication*.
**Thought:** Who changed it, from where, and when?

### 6) Tool/process tells

**Why:** Off-the-shelf tools leave process crumbs.
**Look For (Sysmon/4688):** `rubeus.exe`, `setspn.exe -q`, `adfind.exe`, `GetUserSPNs.py`, `klist`. Parents like `cmd.exe`, `powershell.exe`.
**Thought:** Did this run on a server/DC or random workstation?

### 7) Follow-on credential use

**Why:** Cracked creds get used fast.
**Look For:** **4624 Type 3** bursts by the roasted account to multiple hosts; admin shares / service creation soon after.

---

## 🔎 QRadar AQL (ready to paste; adjust DSM field names)

### A) Kerberoast RC4 tickets (4769)

```sql
SELECT starttime, sourceip, username, "Service Name" AS spn, "Ticket Encryption Type" AS enc
FROM events
WHERE qidname ILIKE '%4769%'
  AND enc IN ('0x17','RC4','rc4-hmac')
ORDER BY starttime DESC
LAST 7 DAYS
```

### B) One user/IP pulling many SPNs (sweep)

```sql
SELECT sourceip, username, COUNT(DISTINCT "Service Name") AS uniq_spn,
       MIN(starttime) AS first_hit, MAX(starttime) AS last_hit
FROM events
WHERE qidname ILIKE '%4769%'
GROUP BY sourceip, username
HAVING uniq_spn >= 10 AND (last_hit - first_hit) <= 900
ORDER BY last_hit DESC
LAST 24 HOURS
```

### C) AS-REP roast success (4768 without preauth)

```sql
SELECT starttime, sourceip, username, "Pre-Authentication Type" AS preauth
FROM events
WHERE qidname ILIKE '%4768%'
  AND (preauth IS NULL OR preauth = '' OR preauth = '0')
ORDER BY starttime DESC
LAST 7 DAYS
```

### D) AS-REP scouting (4771 failures burst)

```sql
SELECT sourceip, COUNT(*) AS fails, MIN(starttime) AS first_seen, MAX(starttime) AS last_seen
FROM events
WHERE qidname ILIKE '%4771%'
  AND "Failure Code" IN ('0x18','KDC_ERR_PREAUTH_REQUIRED')
GROUP BY sourceip
HAVING fails >= 20 AND (last_seen - first_seen) <= 900
ORDER BY last_seen DESC
LAST 24 HOURS
```

### E) UAC flipped to DONT\_REQ\_PREAUTH (4738)

```sql
SELECT starttime, username AS changed_user, sourceip, "Changed Attributes" AS attrs
FROM events
WHERE qidname ILIKE '%4738%'  -- A user account was changed
  AND (attrs ILIKE '%Does not require Kerberos preauthentication%' OR attrs ILIKE '%DONT_REQ_PREAUTH%')
ORDER BY starttime DESC
LAST 30 DAYS
```

### F) Tooling on endpoints (4688 / Sysmon 1)

```sql
SELECT starttime, hostname, username, processname, command
FROM events
WHERE categoryname ILIKE 'Process Created%'
  AND (processname ILIKE '%rubeus%.exe' OR processname ILIKE '%setspn%.exe'
       OR processname ILIKE '%adfind%.exe' OR command ILIKE '%GetUserSPNs.py%')
ORDER BY starttime DESC
LAST 14 DAYS
```

---

## 🛠 Velociraptor VQL (DCs/endpoints)

### 1) 4769 RC4 tickets

```vql
SELECT Timestamp, Computer, EventData.ServiceName AS SPN,
       EventData.TicketEncryptionType AS EncType,
       EventData.IpAddress AS SrcIP, EventData.TargetUserName AS Requester
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
WHERE EventID = 4769 AND (EncType =~ '(?i)0x17|rc4')
ORDER BY Timestamp DESC
```

### 2) SPN sweep from one source

```vql
SELECT SrcIP, count(distinct SPN) AS UniqueSPNs,
       min(Timestamp) AS FirstSeen, max(Timestamp) AS LastSeen
FROM (
  SELECT timestamp(epoch=System.TimeCreated) AS Timestamp,
         EventData.IpAddress AS SrcIP, EventData.ServiceName AS SPN
  FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
  WHERE EventID = 4769
)
GROUP BY SrcIP
HAVING UniqueSPNs >= 10 AND (LastSeen - FirstSeen) <= 900
ORDER BY LastSeen DESC
```

### 3) AS-REP success (4768 w/ no preauth)

```vql
SELECT Timestamp, Computer, EventData.TargetUserName AS User, EventData.IpAddress AS SrcIP,
       EventData.PreAuthType AS PreAuth
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
WHERE EventID = 4768 AND (PreAuth = '' OR PreAuth = '0' OR PreAuth IS NULL)
ORDER BY Timestamp DESC
```

### 4) AS-REP scouting (4771 0x18 bursts)

```vql
SELECT SrcIP, COUNT(*) AS Fails, MIN(TS) AS First, MAX(TS) AS Last
FROM (
  SELECT timestamp(epoch=System.TimeCreated) AS TS,
         EventData.IpAddress AS SrcIP, EventData.FailureCode AS Fail
  FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
  WHERE EventID = 4771 AND Fail =~ '(?i)0x18'
)
GROUP BY SrcIP
HAVING Fails >= 20 AND (Last - First) <= 900
ORDER BY Last DESC
```

### 5) 4738: UAC flipped to roastable

```vql
SELECT Timestamp, Computer, EventData.TargetUserName AS User, EventData.SubjectUserName AS Actor,
       EventData.UserAccountControl AS UAC, EventData.ChangeAttributes AS Attrs
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
WHERE EventID = 4738 AND (Attrs =~ '(?i)Does not require Kerberos preauthentication|DONT_REQ_PREAUTH')
ORDER BY Timestamp DESC
```

### 6) Tool/process tells (Sysmon + Security 4688)

```vql
-- Sysmon ProcessCreate
SELECT Timestamp, Computer, EventData.Image, EventData.CommandLine
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx')
WHERE EventID = 1 AND (lower(EventData.Image) =~ 'rubeus.exe'
    OR lower(EventData.Image) =~ 'setspn.exe'
    OR lower(EventData.CommandLine) =~ 'getuserspns.py'
    OR lower(EventData.Image) =~ 'adfind.exe')

-- Security 4688 fallback
SELECT Timestamp, Computer, EventData.NewProcessName, EventData.CommandLine
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
WHERE EventID = 4688 AND (lower(EventData.NewProcessName) =~ 'rubeus.exe'
    OR lower(EventData.NewProcessName) =~ 'setspn.exe'
    OR EventData.CommandLine =~ '(?i)GetUserSPNs.py'
    OR lower(EventData.NewProcessName) =~ 'adfind.exe')
```

---

## 🧠 Summary

* **Kerberoast:** 4769 + **RC4 (0x17)** + high-cardinality SPNs from a single source.
* **AS-REP roast:** 4768 **success without preauth**, often preceded by 4771 sweeps or 4738 UAC flips.
* Close the loop by watching for **new 4624 Type 3** logons using the roasted accounts; that’s your pivot.
