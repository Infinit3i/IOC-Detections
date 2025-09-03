> 🎯 **Objective**: Detect and stop **VPN credential stuffing** (password spraying + reused creds) against your remote-access portal **before** it turns into a valid session and lateral movement.

---

## ✅ Hypothesis

> “An adversary (or botnet) is hammering the VPN portal with known/leaked username\:password combos. We’ll see bursts of failed logins from one IP/ASN across many users, or the same user probed from many IPs, followed by a ‘golden’ success—often with new geo/UA and rapid MFA prompts.”

---

## 🧱 Tactics to Focus On

1. **Initial Access** — High-rate VPN auth failures, distributed botnet sources
2. **Credential Access** — Use of leaked creds; password spraying (low attempts per user, high users per IP)
3. **Defense Evasion** — Rotate IPs/ASNs, realistic UAs, slow-roll to avoid lockouts
4. **Persistence/Follow-On** — Success→token issuance→privileged groups, split-tunnel egress, quick SMB/RDP

---

## 🔍 Hunt Steps (True Threat Hunt Chain)

### 1) Spike-hunt failures per source

**Why:** Stuffing = one IP hitting many accounts.
**Look for:** Same `src_ip` failing **≥10 users in ≤5 min** (noisy) or slow-roll **≥20 users in ≤60 min**.

### 2) Fan-in against one user

**Why:** Distributed stuffing = many IPs on one account.
**Look for:** Same `username` failed by **≥10 distinct src\_ip** in **≤10 min**.

### 3) Success-after-fail (the payoff)

**Why:** The “one success” amid failures.
**Look for:** Success for a user within **0–15 min** after **≥5** failures (same or different IP). Flag if **new geo/ASN/UA**.

### 4) Geo-velocity & profile mismatch

**Why:** Impossible travel and device anomalies scream takeover.
**Look for:** Prior success from Geo A; new success from Geo B **<2h** later; or brand-new UA on VPN.

### 5) MFA fatigue/abuse (if applicable)

**Why:** Push bombing → eventual approve.
**Look for:** Many `deny/timeout` challenges → single `approve` from **same username** in short window.

### 6) Lockouts & error codes (NPS/RADIUS/VPN)

**Why:** Spray patterns leave 6273/denied streaks and lockouts.
**Look for:** Bursts of **denied** with similar **Reason/Failure** codes, then a lone **granted** (6272).

### 7) Post-login confirmation

**Why:** Real compromise moves fast.
**Look for:** New VPN success → within **0–5 min**, SMB/RDP/HTTP to internal assets, or group/token changes.

---

## 🧠 Summary

Call it when you see **(1) many users from one IP** or **(2) many IPs against one user**, plus **(3) a fresh success** (new geo/UA/MFA pattern). That combo = **account takeover via stuffing**. Cut access, reset passwords, invalidate tokens/sessions, and hunt the post-login pivot.

---

# 🔎 QRadar AQL (swap field names to your DSM)

### A) Spray from one IP (many users, short window)

```sql
SELECT sourceip, COUNT(DISTINCT username) AS uniq_users,
       MIN(starttime) AS first_seen, MAX(starttime) AS last_seen
FROM events
WHERE categoryname ILIKE 'VPN Authentication%'
  AND (outcome ILIKE 'fail%' OR eventname ILIKE '%denied%' OR qidname ILIKE '%failed%')
LAST 60 MINUTES
GROUP BY sourceip
HAVING uniq_users >= 10 AND (last_seen - first_seen) <= 300
ORDER BY uniq_users DESC
```

### B) Distributed spray against one user (many IPs)

```sql
SELECT username, COUNT(DISTINCT sourceip) AS uniq_ips,
       MIN(starttime) AS first_seen, MAX(starttime) AS last_seen
FROM events
WHERE categoryname ILIKE 'VPN Authentication%'
  AND (outcome ILIKE 'fail%' OR eventname ILIKE '%denied%')
LAST 10 MINUTES
GROUP BY username
HAVING uniq_ips >= 10
ORDER BY uniq_ips DESC
```

### C) Success-after-fail (golden hit)

```sql
SELECT s.username, s.sourceip AS success_ip, s.starttime AS success_time, s.useragent
FROM events s
WHERE s.categoryname ILIKE 'VPN Authentication%' AND (s.outcome ILIKE 'success%' OR s.eventname ILIKE '%granted%')
  AND EXISTS (
    SELECT 1 FROM events f
    WHERE f.categoryname ILIKE 'VPN Authentication%'
      AND (f.outcome ILIKE 'fail%' OR f.eventname ILIKE '%denied%')
      AND f.username = s.username
      AND (s.starttime - f.starttime) BETWEEN 0 AND 900
  )
LAST 24 HOURS
ORDER BY s.starttime DESC
```

### D) Impossible travel / new geo (requires geo fields)

```sql
SELECT a.username, a.sourcegeo AS prev_geo, b.sourcegeo AS new_geo, a.starttime AS prev_t, b.starttime AS new_t
FROM events a
JOIN events b ON a.username=b.username AND b.starttime > a.starttime
WHERE a.categoryname ILIKE 'VPN Authentication%' AND b.categoryname ILIKE 'VPN Authentication%'
  AND a.outcome ILIKE 'success%' AND b.outcome ILIKE 'success%'
  AND (b.starttime - a.starttime) <= 7200
  AND a.sourcegeo <> b.sourcegeo
LAST 24 HOURS
ORDER BY b.starttime DESC
```

### E) MFA fatigue (deny/timeout → approve) — if MFA logs land in QRadar

```sql
SELECT username, COUNT(*) AS challenges, MIN(starttime) AS first_t, MAX(starttime) AS last_t
FROM events
WHERE categoryname ILIKE 'MFA%' AND (eventname ILIKE '%deny%' OR eventname ILIKE '%timeout%')
LAST 30 MINUTES
GROUP BY username
HAVING challenges >= 5
ORDER BY last_t DESC;
-- Pair with a success:
SELECT * FROM events
WHERE categoryname ILIKE 'MFA%' AND eventname ILIKE '%approve%'
  AND username IN ( /* usernames from query above */ )
LAST 30 MINUTES
```

### F) NPS/RADIUS denies (Windows 6273) burst

```sql
SELECT sourceip, COUNT(*) AS denies, MIN(starttime) AS first_t, MAX(starttime) AS last_t
FROM events
WHERE qidname ILIKE '%6273%' OR eventname ILIKE '%Network Policy Server denied access%'
LAST 15 MINUTES
GROUP BY sourceip
HAVING denies >= 20 AND (last_t - first_t) <= 900
ORDER BY denies DESC
```

---

# 🛠 Velociraptor VQL (on Windows NPS/RRAS or VPN-adjacent servers)

### 1) NPS grants/denies (Security.evtx 6272/6273)

```vql
SELECT Timestamp, Computer,
       EventID, EventData.UserName AS User, EventData.CallingStationID AS SrcIP,
       EventData.ReasonCode AS Reason, EventData.AuthenticationType AS Auth
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
WHERE EventID IN (6272, 6273)  -- granted / denied
ORDER BY Timestamp DESC
```

### 2) Spray from one IP (many users → denies)

```vql
SELECT SrcIP, COUNT(DISTINCT User) AS Users, MIN(TS) AS First, MAX(TS) AS Last
FROM (
  SELECT timestamp(epoch=System.TimeCreated) AS TS,
         EventData.CallingStationID AS SrcIP, EventData.UserName AS User
  FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
  WHERE EventID = 6273
)
GROUP BY SrcIP
HAVING Users >= 10 AND (Last - First) <= 300
ORDER BY Users DESC
```

### 3) Distributed against one user (many IPs → denies)

```vql
SELECT User, COUNT(DISTINCT SrcIP) AS IPs, MIN(TS) AS First, MAX(TS) AS Last
FROM (
  SELECT timestamp(epoch=System.TimeCreated) AS TS,
         EventData.CallingStationID AS SrcIP, EventData.UserName AS User
  FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
  WHERE EventID = 6273
)
GROUP BY User
HAVING IPs >= 10 AND (Last - First) <= 600
ORDER BY IPs DESC
```

### 4) Success after burst of denies (takeover tell)

```vql
LET denies = SELECT EventData.UserName AS User, MAX(timestamp(epoch=System.TimeCreated)) AS LastDeny
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
WHERE EventID = 6273
GROUP BY User;

SELECT g.Timestamp AS SuccessTime, g.EventData.UserName AS User, g.EventData.CallingStationID AS SrcIP
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx') AS g
JOIN denies USING User
WHERE g.EventID = 6272 AND (g.Timestamp - LastDeny) BETWEEN 0 AND 900
ORDER BY SuccessTime DESC
```

### 5) Client-side VPN (RasClient/Operational) — optional

```vql
SELECT timestamp(epoch=System.TimeCreated) AS TS, Computer,
       EventID, EventData.EntryName AS Profile, EventData.ErrorCode AS Code
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-RasClient%4Operational.evtx')
WHERE EventID IN (20226, 20227, 20271)  -- connect/disconnect/errors
ORDER BY TS DESC
```

---

### Tuning tips

* Allow-list jump boxes and known admin IPs/ASNs; everything else gets throttled or challenged.
* Thresholds above are sane defaults—tighten in peak hours, loosen off-hours.
* Pair **success-after-fail** with **new UA/geo** or **MFA anomaly** to push confidence to “high.”
