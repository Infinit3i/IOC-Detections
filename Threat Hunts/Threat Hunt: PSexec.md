> 🎯 **Objective**: Detect **SMB PsExec-style lateral movement** (Sysinternals PsExec, Impacket psexec/smbexec, PAExec, winexe) that uses **ADMIN\$ + remote service creation** to execute commands as **NT AUTHORITY\SYSTEM**, and catch follow-on staging/pivot.

Adversaries copy a helper binary (e.g., `PSEXESVC.exe` or `RemComSvc.exe`) to `\\TARGET\ADMIN$` (→ `C:\Windows\`), create/start a service via **SVCCTL over SMB/RPC**, run commands, then often remove the service and file. Treat any of this as hostile unless it’s a strictly-approved admin pathway.

---

## ✅ Hypothesis

> “A threat actor with valid creds (or NTLM hash) used SMB (445) to write to `ADMIN$`, created a temporary service (`PSEXESVC`, `RemComSvc`, `PAExec`, or look-alike), executed commands as SYSTEM, and then cleaned up.”

---

## 🧱 Tactics to Focus On

1. **Lateral Movement** — Copy helper binaries via `ADMIN$`, execute via SVCCTL
2. **Execution** — `SYSTEM`-level command lines (`cmd.exe /c …`) spawned by temp services
3. **Credential Access** — **Pass-the-Hash**/NTLM reuse (LogonType 3 bursts)
4. **Defense Evasion** — Short-lived services, named pipes, quick delete from `C:\Windows\`
5. **Staging** — Dropped tools under `%WINDIR%`, `%TEMP%`, or via UNC paths

---

## 🔍 Hunt Steps (True Threat Hunt Chain)

---

### **1) Baseline & spike-hunt SMB to many hosts**

**Why:** PsExec campaigns fan out on 445 from a single source.

**Look For:**

* **NetFlow/Firewall/EDR**: one source connecting to many internal IPs on **445** in short bursts
* **Sysmon EID 3** on the **source**: spikes of `DestinationPort=445`

**Thought Process:**

> Is this an admin jump box during a known window, or a user workstation doing fan-out?

---

### **2) Share access & file writes to ADMIN\$ / IPC\$ on target**

**Why:** The helper binary lands via `\\TARGET\ADMIN$` (maps to `C:\Windows\`).

**Look For (Windows Security):**

* **EID 5140**: “network share object was accessed” → `\\*\ADMIN$`, `\\*\IPC$`
* **EID 5145**: write/create under **Relative Target Name** like `\Windows\PSEXESVC.exe`, `\Windows\RemComSvc.exe`, `\Windows\PAExec.exe`

**Thought Process:**

> Who wrote **what** into `C:\Windows\` and from **where**?

---

### **3) Service creation & start (the smoking gun)**

**Why:** Remote SVCCTL creates/starts a temporary service to run your command.

**Look For:**

* **System log 7045**: “A service was installed” → **Service Name** in `{PSEXESVC|RemComSvc|PAExec|winexesvc}` (or random but suspicious) and **ImagePath** in `C:\Windows\*.exe`
* **System 7036/7035**: service started/stopped; **Security 4697** (if audited): service installed

**Thought Process:**

> Was a short-lived service created with a generic name and deleted quickly?

---

### **4) Command execution as SYSTEM**

**Why:** The service typically launches `cmd.exe /c <payload>` as **SYSTEM**.

**Look For:**

* **Security 4688** / **Sysmon EID 1** on the **target**:

  * Parent: the temp service binary or `services.exe`
  * Child: `cmd.exe /c …`, `powershell.exe -enc …`, `rundll32.exe`, `reg.exe`, `net.exe`, `whoami.exe`, `ipconfig.exe`, `nltest.exe`
* Command lines referencing **UNC** paths, or immediate staging (`bitsadmin`, `curl`, `wget` via Cygwin/MSYS)

**Thought Process:**

> Do we see **SYSTEM** executing operator-style one-liners from a just-installed service?

---

### **5) Named pipe clues**

**Why:** PsExec/RemCom use distinct pipes.

**Look For (Sysmon):**

* **EID 17/18** (Pipe Created/Connected): `\PSEXESVC`, `\RemCom_communication`, and generic `\svcctl`

**Thought Process:**

> Pipes line up with service events? If yes, it’s almost certainly PsExec-style.

---

### **6) Lateral logons & PtH hints**

**Why:** Attackers reuse creds/hashes widely.

**Look For (Security):**

* **EID 4624** with **LogonType=3** from the **same source** into **3+ hosts** within minutes
* **AuthenticationPackage=NTLM** spikes (PtH likely), **Account Name** local admin or DA

**Thought Process:**

> Is this normal admin behavior? If not, this is your pivot path.

---

### **7) Cleanup/Evasion**

**Why:** They often tidy up to reduce artifacts.

**Look For:**

* **File deletes** of `PSEXESVC.exe`/`RemComSvc.exe` from `C:\Windows\` (Sysmon EID 23/24)
* Service removed (no explicit “delete” event; infer via 7036 stop without future starts)
* Short interval from **5145 write** → **7045 create** → **7036 stop** → **delete**

**Thought Process:**

> Did the binary exist only for a few minutes?

---

### **Command Examples (for context)**

```powershell
# Sysinternals
psexec \\HOST -u DOMAIN\admin -p '...' -s -d cmd.exe /c whoami

# Impacket
impacket-psexec 'DOMAIN/Administrator@HOST' -hashes LMHASH:NTHASH "cmd.exe /c whoami"

# PAExec
paexec \\HOST -u DOMAIN\admin -p '...' -s -i 0 cmd.exe /c hostname
```

---

## 🧠 Summary

Chain the story, don’t look at one event in isolation:

* **Write** to `ADMIN$` → **7045** service install → **SYSTEM** command exec → **pipes** (`\PSEXESVC`/`RemCom_communication`) → **stop & delete**
* Correlate with **4624 type 3** bursts and upstream **445** fan-out from a single source.
* Unless it’s a blessed admin pathway, treat it as a **lateral movement incident**.

---

# 🔎 “New search functions” add-ons

Below are **succinct, ready-to-paste** queries for your stack. Tune field names to your DSM/log mappings.

## QRadar AQL

### A) Service creation (7045) — classic PsExec/RemCom/PAExec

```sql
SELECT starttime, hostname, "Service Name" AS svc, "Service File Name" AS imagepath, username, sourceip
FROM events
WHERE (qidname ILIKE '%7045%' OR eventname ILIKE '%A service was installed%')
  AND (svc ILIKE '%PSEXESVC%' OR svc ILIKE '%RemComSvc%' OR svc ILIKE '%PAExec%' OR svc ILIKE '%winexesvc%')
ORDER BY starttime DESC
LAST 30 DAYS
```

### B) Share access/write to ADMIN\$ / IPC\$ (5140/5145)

```sql
SELECT starttime, destinationip AS target, sourceip AS client, username,
       "Share Name" AS share, "Relative Target Name" AS path, action
FROM events
WHERE (qidname ILIKE '%5140%' OR qidname ILIKE '%5145%' OR eventname ILIKE '%network share object was accessed%')
  AND (share ILIKE '%ADMIN$%' OR share ILIKE '%IPC$%')
  AND (action ILIKE '%Write%' OR path ILIKE '%\\Windows\\PSEXESVC.exe%' OR path ILIKE '%\\Windows\\RemCom%')
ORDER BY starttime DESC
LAST 7 DAYS
```

### C) SYSTEM cmd spawned by temp service (4688 / Sysmon 1)

```sql
SELECT starttime, hostname, username, parentprocessname, processname, command
FROM events
WHERE categoryname ILIKE 'Process Created%'
  AND (parentprocessname ILIKE '%services.exe%' OR parentprocessname ILIKE '%PSEXESVC%' OR parentprocessname ILIKE '%RemComSvc%')
  AND (processname ILIKE '%cmd.exe%' OR processname ILIKE '%powershell.exe%' OR command ILIKE '% /c %')
ORDER BY starttime DESC
LAST 7 DAYS
```

### D) Named pipes (Sysmon 17/18)

```sql
SELECT starttime, hostname, username, "Pipe Name" AS pipe, processname, command
FROM events
WHERE (qidname ILIKE '%Sysmon Event ID 17%' OR qidname ILIKE '%Sysmon Event ID 18%')
  AND (pipe ILIKE '%\\PSEXESVC%' OR pipe ILIKE '%\\RemCom_communication%' OR pipe ILIKE '%\\svcctl%')
ORDER BY starttime DESC
LAST 30 DAYS
```

### E) Lateral logons burst (4624 Type 3)

```sql
SELECT username, sourceip, COUNT(*) AS hops, MIN(starttime) AS first_seen, MAX(starttime) AS last_seen
FROM events
WHERE qidname ILIKE '%4624%' AND "Logon Type" = 3
GROUP BY username, sourceip
HAVING hops >= 3
ORDER BY last_seen DESC
LAST 24 HOURS
```

---

## Velociraptor VQL

### A) System.evtx — 7045/7036/7035 service lifecycle

```vql
SELECT Timestamp, Computer, EventID,
       EventData.ServiceName AS SvcName, EventData.ImagePath AS ImagePath, EventData.State
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\System.evtx')
WHERE EventID IN (7045,7036,7035)
  AND (SvcName =~ '(?i)(PSEXESVC|RemComSvc|PAExec|winexesvc)' OR ImagePath =~ '(?i)\\\\Windows\\\\.*(psexesvc|remcom|paexec).*')
ORDER BY Timestamp DESC
```

### B) Security.evtx — 5140/5145 ADMIN\$/IPC\$ and 4688

```vql
-- Share access/writes
SELECT Timestamp, Computer, EventID, EventData.ShareName AS Share, EventData.RelativeTargetName AS Path,
       EventData.SubjectUserName AS User, EventData.IpAddress AS SrcIP, EventData.AccessList AS Access
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
WHERE EventID IN (5140,5145)
  AND Share =~ '(?i)(ADMIN\\$|IPC\\$)'

-- Process creation
SELECT Timestamp, Computer, EventID, EventData.NewProcessName AS Image, EventData.CommandLine, EventData.ParentProcessName AS Parent
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
WHERE EventID = 4688
  AND (Parent =~ '(?i)(services\\.exe|psexesvc|remcomsvc|paexec)'
       OR CommandLine =~ '(?i)\\scmd\\.exe\\s*/c\\s+')
```

### C) Sysmon — Process + Pipes

```vql
-- Sysmon Operational: ProcessCreate + Pipe events
SELECT Timestamp, Computer, EventID,
       EventData.Image, EventData.CommandLine, EventData.ParentImage, EventData.PipeName
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx')
WHERE (EventID = 1 AND (ParentImage =~ '(?i)(services\\.exe|psexesvc|remcomsvc|paexec)'))
   OR (EventID IN (17,18) AND (EventData.PipeName =~ '(?i)(\\\\PSEXESVC|\\\\RemCom_communication|\\\\svcctl)'))
ORDER BY Timestamp DESC
```

### D) File artifacts & Prefetch residue

```vql
-- Did the helper binary touch disk?
SELECT OSPath, stat.Mtime AS MTime, stat.Size
FROM glob(globs=['C:\\Windows\\PSEXESVC.exe','C:\\Windows\\RemComSvc.exe','C:\\Windows\\PAExec.exe'])
WHERE stat.Exists

-- Prefetch: useful on workstations/servers with Prefetch enabled
SELECT * FROM artifact.Windows.Forensics.Prefetch()
WHERE lower(ImagePath) =~ '(psexec|paexec|remcom)'
```

### E) Registry services residue

```vql
SELECT FullPath, Name, Data
FROM winreg(key='HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services')
WHERE Name =~ '(?i)(PSEXESVC|RemComSvc|PAExec|winexesvc)'
```

---

### Tuning / Reality checks

* Expect some legitimate admin use. Put **allow-lists** around known jump boxes, windows, and groups.
* Impacket often uses **random service names**; keep patterning on **ImagePath in `C:\Windows\`** and the **pipe set** plus **4624 type 3 bursts**.
* If 5145 isn’t enabled, lean on **7045 + 4688 + Sysmon pipes**.
* For PtH, stacking on **NTLM** auth frequency by source helps separate real admin (Kerberos) from bad ops.
