> 🎯 **Objective**: Catch **PowerShell encoded-command execution** (`-enc` / `-encodedcommand`) used for initial execution, payload staging, and lateral actions—**especially** when it’s buried behind LOLBins or service exec to dodge string-based detections.

Attackers base64-encode payloads (usually **UTF-16LE**) and run them via `powershell.exe -enc <blob>` with flags like `-nop -w hidden -ep bypass`. Your job: chain the network, process, and event clues—not just grep for `-enc`.

---

## ✅ Hypothesis

> “An attacker executed **powershell.exe** with **-encodedcommand**, decoded a base64 payload (UTF-16LE), and executed it to stage tools, beacon, or move laterally—likely from a service, scheduled task, WMI, or PsExec context.”

---

## 🧱 Tactics to Focus On

1. **Execution** — `powershell.exe -enc <b64>` with stealth flags (`-nop -w hidden -ep bypass`)
2. **Defense Evasion** — Obfuscated base64, nested `FromBase64String() | IEX`, transient parent (e.g., `services.exe`, `wmiprvse.exe`)
3. **Discovery/Staging** — Download/execute (`WebClient.DownloadString`, `IEX`, `bitsadmin`, `Invoke-WebRequest`)
4. **Lateral Movement** — Fired by service/WMI/Task Scheduler/SMB PsExec on remote hosts
5. **Cleanup** — Clearing PS history, disabling 4104, deleting staged files

---

## 🔍 Hunt Steps (True Threat Hunt Chain)

### **1) Find encoded-command launches (source of truth: process start)**

**Why:** If `-enc` exists, that’s already high-signal.

**Look For:**

* **4688** / **Sysmon EID 1** on endpoints:

  * `NewProcessName: *\powershell.exe`
  * `CommandLine` contains `-enc` or `-encodedcommand`
  * Flags: `-nop`, `-w hidden`, `-ep bypass`
* Parents: `services.exe`, `wmiprvse.exe`, `taskeng.exe`, `schtasks.exe`, `psexesvc.exe`, `remcomsvc.exe`, `winlogon.exe` (logon scripts)

**Thought Process:**

> Who launched PowerShell? A user, a scheduled task, or a service? Is the parent plausible?

---

### **2) Validate the decoded intent (script block / decode patterns)**

**Why:** Even if 4104 is disabled, code often reveals itself elsewhere.

**Look For:**

* **PowerShell/Operational 4104** (if enabled): script text containing `FromBase64String`, `IEX`, `DownloadString`, `Add-Type`, `Reflection.Assembly::Load`
* If 4104 missing: 4688 `CommandLine` often still shows the base64 blob—decode it out-of-band and scan for behaviors.

**Thought Process:**

> Does the decoded script do staging, beacon setup, or credential actions?

---

### **3) Correlate immediate follow-on activity**

**Why:** Real ops do something right after decode.

**Look For (within 0–120s of step 1):**

* New **network egress** to rare domains/IPs (Arkime/Netflow)
* **File writes** to `%TEMP%`, `%ProgramData%`, user profile temp; creation of `.dll/.ps1/.exe`
* **Process tree**: `powershell.exe` → `cmd.exe`/`rundll32.exe`/`reg.exe`/`bitsadmin.exe`/`mshta.exe`

**Thought Process:**

> Is this a one-off benign admin script, or did it fetch and run a payload?

---

### **4) Lateral execution context**

**Why:** Encoded PS is frequently the **payload carrier** for PsExec/WMI/Task Scheduler.

**Look For:**

* 4624 **LogonType=3** bursts (same user hits multiple hosts)
* 7045 service install ± `RemComSvc`/random services
* 4688 on **remote hosts**: `powershell.exe -enc ...` with parent `services.exe` or `wmiprvse.exe`

**Thought Process:**

> Is this spreading? If yes, cut creds and isolate source host(s).

---

### **5) Evasion/cleanup indicators**

**Why:** Adversaries neuter visibility.

**Look For:**

* Registry flips disabling ScriptBlock logging
* Deleted PS history: `ConsoleHost_history.txt` missing/zeroed
* Events showing **Engine** start/stop without content (400/403) paired with 4688 `-enc`

**Thought Process:**

> Did someone deliberately kill your PS telemetry?

---

## 🧠 Summary

* **Signal #1**: `powershell.exe` with `-enc` is rarely legit on servers.
* **Prove intent** by decoding blobs or grabbing 4104.
* **Chain** process start → script behavior → egress → file/process artifacts → (optionally) lateral spread.
* If it’s not a known admin script with change control, treat it as an **incident**.

---

# 🔎 QRadar AQL (ready-to-paste)

> Adjust field names to your DSM mappings (`processname`, `command`, `parentprocessname`, `qidname`, etc.).

### A) Catch `-enc` / `-encodedcommand` launches (4688/Sysmon 1)

```sql
SELECT starttime, hostname, username, parentprocessname, processname, command
FROM events
WHERE categoryname ILIKE 'Process Created%'
  AND processname ILIKE '%\\powershell.exe'
  AND (command ILIKE '% -enc %' OR command ILIKE '% -encodedcommand %'
       OR command MATCHES '(?i)-enc(?:odedcommand)?\\s+[A-Za-z0-9+/=]{20,}')
ORDER BY starttime DESC
LAST 7 DAYS
```

### B) High-stealth flag combo (`-nop -w hidden -ep bypass`)

```sql
SELECT starttime, hostname, username, command
FROM events
WHERE categoryname ILIKE 'Process Created%'
  AND processname ILIKE '%\\powershell.exe'
  AND command ILIKE '%-nop%' AND command ILIKE '%-w hidden%'
  AND (command ILIKE '%-ep bypass%' OR command ILIKE '%-executionpolicy bypass%')
ORDER BY starttime DESC
LAST 30 DAYS
```

### C) Parent context = service/WMI/Task (lateral tell)

```sql
SELECT starttime, hostname, username, parentprocessname, command
FROM events
WHERE categoryname ILIKE 'Process Created%'
  AND processname ILIKE '%\\powershell.exe'
  AND (parentprocessname ILIKE '%services.exe%' OR parentprocessname ILIKE '%wmiprvse.exe%' OR parentprocessname ILIKE '%taskeng.exe%' OR parentprocessname ILIKE '%psexesvc%' OR parentprocessname ILIKE '%remcomsvc%')
  AND (command ILIKE '% -enc %' OR command ILIKE '% -encodedcommand %')
ORDER BY starttime DESC
LAST 14 DAYS
```

### D) Follow-on downloader behavior within 2 min

```sql
SELECT e1.starttime AS ps_time, e1.hostname, e1.username, e1.command,
       e2.processname, e2.command AS follow_cmd, e2.starttime AS follow_time
FROM events e1
JOIN events e2 ON e1.hostname = e2.hostname
WHERE e1.categoryname ILIKE 'Process Created%' AND e1.processname ILIKE '%\\powershell.exe'
  AND (e1.command ILIKE '% -enc %' OR e1.command ILIKE '% -encodedcommand %')
  AND e2.categoryname ILIKE 'Process Created%'
  AND (e2.processname ILIKE '%\\cmd.exe' OR e2.processname ILIKE '%\\rundll32.exe' OR e2.processname ILIKE '%\\bitsadmin.exe' OR e2.command ILIKE '%Invoke-WebRequest%' OR e2.command ILIKE '%DownloadString%')
  AND (e2.starttime - e1.starttime) BETWEEN 0 AND 120
ORDER BY follow_time DESC
LAST 48 HOURS
```

---

# 🛠 Velociraptor VQL (endpoint reality: no native PS telemetry → use EVTX/Sysmon + artifacts)

### 1) Security.evtx — 4688 with `-enc`

```vql
SELECT Timestamp, Computer, EventData.NewProcessName AS Image, EventData.CommandLine AS Cmd,
       EventData.ParentProcessName AS Parent
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
WHERE EventID = 4688
  AND lower(Image) =~ 'powershell.exe'
  AND (Cmd =~ '(?i)\\s-enc\\s' OR Cmd =~ '(?i)-encodedcommand\\s')
ORDER BY Timestamp DESC
```

### 2) Sysmon — ProcessCreate (EID 1) + service/WMI parents

```vql
SELECT Timestamp, Computer, EventData.Image, EventData.CommandLine, EventData.ParentImage
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx')
WHERE EventID = 1
  AND lower(EventData.Image) =~ 'powershell.exe'
  AND (EventData.CommandLine =~ '(?i)-enc(odedcommand)?\\s+[A-Za-z0-9+/=]{20,}'
       OR (EventData.CommandLine =~ '(?i)-nop' AND EventData.CommandLine =~ '(?i)-w\\s*hidden'))
  AND (EventData.ParentImage =~ '(?i)services\\.exe|wmiprvse\\.exe|taskeng\\.exe|psexesvc|remcomsvc')
ORDER BY Timestamp DESC
```

### 3) Decode the blob (quick triage of likely UTF-16LE base64)

```vql
LET rows = SELECT Timestamp, Computer, EventData.CommandLine AS Cmd
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Security.evtx')
WHERE EventID = 4688 AND lower(EventData.NewProcessName) =~ 'powershell.exe'
  AND Cmd =~ '(?i)-enc(odedcommand)?\\s+([A-Za-z0-9+/=]{20,})';

SELECT Timestamp, Computer, Cmd,
       text(string=try_utf16le(bytes=base64decode(string=regex_extract(Cmd, '(?i)-enc(?:odedcommand)?\\s+([A-Za-z0-9+/=]{20,})', 1)))) AS Decoded
FROM rows
```

> **Tip:** Hunt decoded text for `IEX`, `DownloadString`, `Invoke-WebRequest`, `Add-MpPreference`, `FromBase64String`, `Reflection.Assembly::Load`.

### 4) PowerShell/Operational 4104 (if enabled)

```vql
SELECT Timestamp, Computer, EventData.ScriptBlockText AS Script
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx')
WHERE EventID = 4104
  AND (Script =~ '(?i)FromBase64String\\(' OR Script =~ '(?i)Invoke-Expression' OR Script =~ '(?i)DownloadString|Invoke-WebRequest')
ORDER BY Timestamp DESC
```

### 5) Artifacts: history, prefetch, registry

```vql
-- PSReadLine history (often missed but quick win)
SELECT OSPath, stat.Size, stat.Mtime
FROM glob(globs='C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt')

-- Prefetch (where enabled)
SELECT * FROM artifact.Windows.Forensics.Prefetch()
WHERE lower(ImagePath) =~ 'powershell.exe'

-- ScriptBlock logging switches (did someone disable it?)
SELECT Name, Data, FullPath
FROM winreg(key='HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\PowerShell\\3\\PowerShellEngine')
UNION ALL
SELECT Name, Data, FullPath
FROM winreg(key='HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging')
```

---

## Tuning / Triage Notes

* Most admins **don’t** use `-enc` in routine tasks. Treat it as **high-signal** on servers/DCs.
* Expect evasions: nested base64, whitespace tricks, or UTF-8 blobs. The regex above is purposely loose (`{20,}`) to catch real-world blobs.
* If Script Block Logging is off, rely on **4688/Sysmon** and **follow-on behavior** (downloaders, lateral services, egress).
* Stack on **parent caller** and **USER/DEVICE allow-lists** to cut FPs fast.
