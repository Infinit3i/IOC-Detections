> 🎯 **Objective**: Catch **malicious Office macros (VBA/VSTO)** used for initial execution, staging, persistence, or lateral movement—especially when they **spawn LOLBINs**, **touch startup paths**, or **flip macro security**.

---

## ✅ Hypothesis

> “A user opened a booby-trapped Office doc that executed a macro, which spawned child processes (cmd/PowerShell/mshta/regsvr32), wrote payloads to startup locations, altered Trust Center settings, and reached out to external C2.”

---

## 🧱 Tactics to Focus On

1. **Execution** — `WINWORD/EXCEL/POWERPNT/OUTLOOK` → child `cmd.exe`, `powershell.exe`, `wscript/cscript`, `mshta`, `rundll32`, `regsvr32`, `bitsadmin/certutil/curl`.
2. **Defense Evasion** — Macro security weakened (Trust Center), new **Trusted Locations**, disabling AMSI/AV, hiding in template add-ins.
3. **Persistence/Staging** — Drops to `XLSTART` / `Word\Startup` / `VbaProject.otm` (Outlook), COM add-ins.
4. **C2/Delivery** — HTTP(S) from Office process or immediately-spawned LOLBIN, archive/script drops in `%TEMP%` / `%ProgramData%`.
5. **Cleanup** — Deleting staged files, reverting keys.

---

## 🔍 Hunt Steps (True Threat Hunt Chain)

### 1) **Office → LOLBIN** child processes (high-signal)

**Why:** Legit docs don’t pop shells.
**Look for:**

* **Process start (4688 / Sysmon EID 1)** where **ParentImage** is one of:

  * `*\WINWORD.EXE`, `*\EXCEL.EXE`, `*\POWERPNT.EXE`, `*\OUTLOOK.EXE`
* **Image/CommandLine** of child in:

  * `*\cmd.exe`, `*\powershell.exe`, `*\wscript.exe`, `*\cscript.exe`, `*\mshta.exe`, `*\rundll32.exe`, `*\regsvr32.exe`, `*\bitsadmin.exe`, `*\certutil.exe`, `*\curl.exe`
  * Red flags: `-enc`, `-w hidden`, `-nop`, `scrobj.dll`, `/i:http`, `urlcache`, `.. | iex`, `msxml2.xmlhttp`, `ADODB.Stream`.

**Thought process:** Parent Office → any of the above = investigate. Tie to the user and email/source.

---

### 2) **Network from Office** (or immediate child)

**Why:** Macros often fetch second stages.
**Look for:**

* **Network connections (Sysmon EID 3 / firewall / Arkime)** where `Image` is Office or the immediate child from step 1, to **external IPs/domains** within **0–120s** of document open.

**Thought process:** Does Office (or its child) talk to the internet? Rare for normal usage.

---

### 3) **File writes to startup/template locations** (persistence)

**Why:** Durable load via Office auto-load paths.
**Look for (Sysmon EID 11 / FIM):**

* **Excel:** `C:\Users\*\AppData\Roaming\Microsoft\Excel\XLSTART\*`
* **Word:** `C:\Users\*\AppData\Roaming\Microsoft\Word\STARTUP\*`
* **All-user:** `C:\Program Files\Microsoft Office\*\STARTUP\*`
* **Outlook VBA:** `C:\Users\*\AppData\Roaming\Microsoft\Outlook\VbaProject.otm` (recently written)
* **Add-ins:** `C:\Users\*\AppData\Roaming\Microsoft\AddIns\*.xlam|*.dotm|*.ppam`

**Thought process:** Office writing executable/script content into these = likely persistence.

---

### 4) **Macro security & Trusted Locations tampering**

**Why:** Lowering barriers is classic.
**Look for (Sysmon EID 13/14 or Audit registry):**

* `HKCU\Software\Microsoft\Office\<ver>\Word\Security\VBAWarnings`
* `HKCU\Software\Microsoft\Office\<ver>\Excel\Security\VBAWarnings`
* `HKCU\Software\Microsoft\Office\<ver>\Common\Security\Trusted Locations\*` (new paths)
* `AccessVBOM`, `DisableVbaWarnings`, or policy equivalents under `HKLM\Software\Policies\Microsoft\Office\*`

**Thought process:** Recent flips or new trusted paths right before/after step 1 is damning.

---

### 5) **Outlook abuse** (if mail-borne)

**Why:** Outlook forms/rules/VBA can persist and execute.
**Look for:**

* `VbaProject.otm` write + **OUTLOOK.EXE** parent process launches, rule modifications (if audited), or `outlook.exe` → child LOLBIN.

---

### 6) **Cleanup / Anti-forensics**

**Why:** Good ops wipe traces.
**Look for:**

* Deletes in the paths above (Sysmon EID 23/24), registry rollbacks, Office temp files wiped immediately after network activity.

---

## 🧠 Summary

Chain it: **Office parent → LOLBIN child → external egress → file/registry persistence → (optional) cleanup**. If any two of those happen in a tight window, you likely have a malicious macro run. Treat `WINWORD.EXE` spawning `powershell.exe -enc` as hostile until proven innocent.

---

# 🔎 QRadar AQL (ready-to-paste; adjust DSM field names)

### A) Office spawning suspicious children

```sql
SELECT starttime, hostname, username, parentprocessname, processname, command
FROM events
WHERE categoryname ILIKE 'Process Created%'
  AND parentprocessname ILIKE '%\\(WINWORD|EXCEL|POWERPNT|OUTLOOK)\\.EXE%'
  AND (
    processname ILIKE '%\\(cmd|powershell|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil|curl)\\.exe'
    OR command ILIKE '% -enc %' OR command ILIKE '% /i:http%' OR command ILIKE '%scrobj.dll%'
    OR command ILIKE '%FromBase64String%' OR command ILIKE '%Invoke-WebRequest%' OR command ILIKE '%DownloadString%'
  )
ORDER BY starttime DESC
LAST 14 DAYS
```

### B) Network egress tied to Office/child within 2 minutes

```sql
SELECT f.starttime, f.sourceip, f.destinationip, f.destinationport, f.bytes, f.packets, f.application
FROM flows f
WHERE f.sourceip IN (
  SELECT DISTINCT sourceip FROM events
  WHERE categoryname ILIKE 'Process Created%'
    AND (processname ILIKE '%\\(WINWORD|EXCEL|POWERPNT|OUTLOOK)\\.EXE%'
         OR parentprocessname ILIKE '%\\(WINWORD|EXCEL|POWERPNT|OUTLOOK)\\.EXE%')
  LAST 24 HOURS
)
ORDER BY f.starttime DESC
LAST 24 HOURS
```

### C) File writes to Office auto-load paths (needs FIM/Sysmon ingestion)

```sql
SELECT starttime, hostname, username, filename, action
FROM events
WHERE categoryname ILIKE 'File Created%'
  AND (
    filename ILIKE 'C:\\Users\\%\\AppData\\Roaming\\Microsoft\\Excel\\XLSTART\\%' OR
    filename ILIKE 'C:\\Users\\%\\AppData\\Roaming\\Microsoft\\Word\\STARTUP\\%' OR
    filename ILIKE 'C:\\Program Files\\Microsoft Office\\%\\STARTUP\\%' OR
    filename ILIKE 'C:\\Users\\%\\AppData\\Roaming\\Microsoft\\Outlook\\VbaProject.otm' OR
    filename ILIKE 'C:\\Users\\%\\AppData\\Roaming\\Microsoft\\AddIns\\%.(xlam|ppam|dotm)'
  )
ORDER BY starttime DESC
LAST 14 DAYS
```

### D) Macro security / Trusted Locations registry changes

```sql
SELECT starttime, hostname, username, "Registry Key" AS regkey, "Registry Value" AS regvalue, action
FROM events
WHERE categoryname ILIKE 'Registry Value Set%'
  AND (
    regkey ILIKE '%\\Office\\%\\Security\\VBAWarnings%' OR
    regkey ILIKE '%\\Office\\%\\Security\\Trusted Locations\\%' OR
    regkey ILIKE '%\\Office\\%\\Security\\AccessVBOM%' OR
    regkey ILIKE '%\\Policies\\Microsoft\\Office\\%'
  )
ORDER BY starttime DESC
LAST 30 DAYS
```

---

# 🛠 Velociraptor VQL

### 1) Office → LOLBIN child (Sysmon ProcessCreate)

```vql
SELECT Timestamp, Computer, EventData.ParentImage AS Parent, EventData.Image AS Image, EventData.CommandLine AS Cmd
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx')
WHERE EventID = 1
  AND Parent =~ '(?i)\\(WINWORD|EXCEL|POWERPNT|OUTLOOK)\\.exe'
  AND (Image =~ '(?i)\\(cmd|powershell|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil|curl)\\.exe'
       OR Cmd =~ '(?i)\\s-enc\\s|/i:http|scrobj\\.dll|FromBase64String|Invoke-WebRequest|DownloadString')
ORDER BY Timestamp DESC
```

### 2) Network from Office (Sysmon NetConnect)

```vql
SELECT Timestamp, Computer, EventData.DestinationIp AS DstIP, EventData.DestinationPort AS DstPort, EventData.Image
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx')
WHERE EventID = 3
  AND EventData.Image =~ '(?i)\\(WINWORD|EXCEL|POWERPNT|OUTLOOK)\\.exe'
ORDER BY Timestamp DESC
```

### 3) File drops to auto-load paths (Sysmon FileCreate)

```vql
LET paths = [
  'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Excel\\XLSTART\\*',
  'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Word\\STARTUP\\*',
  'C:\\Program Files\\Microsoft Office\\*\\STARTUP\\*',
  'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Outlook\\VbaProject.otm',
  'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\AddIns\\*.xlam',
  'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\AddIns\\*.ppam',
  'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\AddIns\\*.dotm'
];

SELECT Timestamp, Computer, EventData.TargetFilename AS File, EventData.Image AS Writer
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx')
WHERE EventID = 11
  AND ANY(glob(globs=paths), File)
ORDER BY Timestamp DESC
```

### 4) Registry tampering (Sysmon RegSet/RegAdd)

```vql
SELECT Timestamp, Computer, EventData.TargetObject AS Key, EventData.Details, EventData.Image
FROM parse_evtx(filename='C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx')
WHERE EventID IN (12,13,14)
  AND Key =~ '(?i)\\Office\\.*\\Security\\(VBAWarnings|Trusted Locations|AccessVBOM)|\\Policies\\Microsoft\\Office\\'
ORDER BY Timestamp DESC
```

### 5) Outlook VBA persistence artifact (file timestamp check)

```vql
SELECT OSPath, stat.Mtime AS MTime, stat.Size
FROM glob(globs='C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Outlook\\VbaProject.otm')
WHERE stat.Exists
ORDER BY MTime DESC
```

---

## Tuning Tips

* Allow-list known internal add-ins/paths; everything else in **XLSTART/STARTUP** deserves scrutiny.
* On servers, **any** Office → LOLBIN is suspicious. On desktops, scope by **source email**, **user group**, and **time of day**.
* If Script Block logging isn’t available, rely on **process + registry + file + network** correlation—the combo is enough to call it.
