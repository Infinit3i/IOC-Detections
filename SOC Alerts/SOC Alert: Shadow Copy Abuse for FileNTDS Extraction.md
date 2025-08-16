
```text
ALERT: Shadow copy creation (vssadmin/wmic)
    ↓
Access to VolumeShadowCopy path
    ↓
Copying ntds.dit + SYSTEM hive
    ↓
Offline extraction of password hashes
    ↓
Credential abuse (pass-the-hash/ticket)
    ↓
Lateral movement or domain persistence
    ↓
Attempted cleanup (delete shadows, remove dump)
```

## ⚡ Trigger: Alert on `vssadmin.exe` or `wmic.exe` Usage

> SIEM/EDR flags a command like:

```cmd
vssadmin create shadow /for=C:
```

or

```cmd
wmic shadowcopy call create Volume='C:\'
```

---

## 🔍 Step 1: **Creation of Shadow Copy**

**Indicators:**

* `vssadmin.exe`, `wmic.exe`, or PowerShell usage
* Often run as Administrator/SYSTEM
* May use LOLBINs or renamed binaries

**Why this matters:**

* Attackers use shadow copies to create a point-in-time snapshot of locked files (like the AD DB or registry hives)

**Next Questions:**

> Who ran this?
> Was it scripted or interactive?
> Was the tool renamed?

---

## 📂 Step 2: **Accessing Sensitive Files via the Shadow Copy Path**

**Observed Activity:**

* File reads from `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\`
* Tools like `copy`, `7zip`, `xcopy`, or PowerShell used to extract:

  * `C:\Windows\NTDS\ntds.dit`
  * `C:\Windows\System32\config\SYSTEM`

**Why this matters:**

* The attacker is now extracting critical password hashes or system secrets without needing LSASS access.

**Artifacts:**

* Sysmon Event ID 11 (FileCreate) for copied files
* Potential `.zip` or `.7z` containing dumps

**Next Questions:**

> Where did they save the extracted files?
> Were they compressed or obfuscated?
> Are those files still present?

---

## 📡 Step 3: **Tool Usage for Hash Extraction or Offline Analysis**

**Common Tools Used:**

* `secretsdump.py` (Impacket)
* `mimikatz`, `ntdsutil`, or custom offline extractors
* PowerShell scripts loading `.dit` files

**TTP Indicators:**

* Suspicious execution of Python or PowerShell tools
* DLLs/modules related to NTDS parsing
* Unusual access to extracted files

**Next Questions:**

> Did they access the files locally or exfil them?
> Were creds extracted from this box or staged elsewhere?

---

## 🛰 Step 4: **Lateral Movement or Credential Abuse**

**Follow-up Behavior:**

* 4648 events (Explicit logon with extracted creds)
* Kerberos ticket reuse (Pass-the-Ticket)
* NTLM logons from new hosts (Pass-the-Hash)
* Use of accounts found in `ntds.dit`

**Why this matters:**

* This confirms **post-extraction credential abuse**.
* May target Domain Admins or Tier-0 systems

**Next Questions:**

> Are the stolen credentials now active elsewhere?
> Can we correlate logon events to compromised users?

---

## 🧪 Final Check: Signs of Clean-Up or Evasion

**Indicators:**

* Deletion of dump files
* Removal of shadow copies:

```cmd
vssadmin delete shadows /all /quiet
```

* Timestomping or alternate data stream usage (`Zone.Identifier` removal)

**Why this matters:**

* Indicates attacker is trying to **cover tracks**
* Often happens after data exfiltration
