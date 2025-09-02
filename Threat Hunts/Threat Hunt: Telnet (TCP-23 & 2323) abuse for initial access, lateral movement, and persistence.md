> 🎯 **Objective**: Detect **Telnet (TCP/23 & 2323)** abuse for **initial access, lateral movement, and persistence**—especially on **IoT/printers/network gear** and any legacy Windows/Linux hosts—without relying on legacy IDS noise or “it’s just old equipment” excuses.

Telnet is plaintext. If it’s on your network, credentials and commands are traveling in the clear. Attackers love it for quick wins (default creds/brute force), easy remote shells, and backdooring by **enabling telnetd/TlntSvr** where it shouldn’t exist.

---

## ✅ Hypothesis

> “A threat actor is authenticating to exposed or legacy devices over Telnet using default/stolen credentials, enabling/abusing Telnet services for persistence, and pivoting from those footholds into the internal network.”

---

## 🧱 Tactics to Focus On

1. **Initial Access** — Default creds/brute force against IoT, printers, switches, old servers
2. **Lateral Movement** — Interactive shells over Telnet from compromised “non-user” devices
3. **Persistence** — Enabling **telnetd** (Linux/BusyBox) or **TlntSvr** (Windows)
4. **Credential Access** — Plaintext creds in-flight; sniffable on the segment
5. **Defense Evasion** — BusyBox tooling, renamed binaries, ephemeral `/tmp` droppers
6. **Staging/Delivery** — `wget/curl/tftp` chains right after login

---

## 🔍 Hunt Steps (True Threat Hunt Chain)

---

### **1. Hunt for Telnet Network Activity (it should be rare)**

**Why:** Modern environments have no good reason for 23/2323. Any is suspect.

**Look For:**

* **Sysmon EID 3** (Windows): `DestinationPort=23 OR 2323`; `Image` like `telnet.exe`, `cmd.exe`, `powershell.exe` spawning `telnet`
* **Windows Security EID 5156** (WFP permitted connection): DestPort `23/2323`
* **Zeek** `conn.log`: `service=telnet`; **Suricata/IDS** telnet negotiation/bruteforce signatures
* **NetFlow/Firewall**: scans/fan-out to many hosts on 23/2323

**Thought Process:**

> Who is talking Telnet at all? Is this a printer/camera… or a user workstation (worse)?

---

### **2. Detect Telnet Service Enablement for Backdoor**

**Why:** Attackers flip Telnet **on** to keep coming back.

**Look For:**

* **Windows**

  * **Service Control Manager**: EID **7045** (service created) / **7036** (started) for **`TlntSvr` / Telnet**
  * **Sysmon EID 1**: `dism.exe`, `sc.exe`, `tlntadmn.exe` enabling Telnet features/services
  * **Sysmon EID 12/13**: Registry changes under `HKLM\SYSTEM\CurrentControlSet\Services\TlntSvr\*`
* **Linux/BusyBox**

  * Processes: `in.telnetd`, `telnetd` (often via **inetd/xinetd/systemd**)
  * Files/Config: `/etc/xinetd.d/telnet`, `systemctl enable telnet.socket`, BusyBox `telnetd -l /bin/sh -p 23`

**Thought Process:**

> Did Telnet get turned on somewhere it wasn’t before?

---

### **3. Surface Brute-Force / Default Cred Attempts**

**Why:** IoT botnets and lazy intruders hammer Telnet first.

**Look For:**

* **IDS**: repeated failed logins; telnet auth errors; same source ➜ many targets
* **Linux `/var/log/auth.log`**: `FAILED LOGIN` via `telnetd` / PAM; bursts across minutes
* **Network devices**: TACACS/RADIUS failures on **vty** lines (if you aggregate those logs)

**Thought Process:**

> Are we seeing dictionary bursts and then a single success before a quiet pause?

---

### **4. Catch the Post-Login Downloader Chain**

**Why:** First thing after Telnet login: pull a payload.

**Look For:**

* **PCAP/IDS payloads** showing:
  `wget http://…`, `curl … | sh`, `tftp -g -r <file>`, `chmod +x`, `./<bin>`
  BusyBox banners, architecture strings (MIPS/ARM/x86), or strings like `mozi`, `gafgyt`
* **Correlation**: Telnet login ➜ seconds later **HTTP/TFTP** outbound from same host
* **Filesystem (Linux)**: new files in `/tmp`, `/dev/shm`, `/var/run` with random names

**Thought Process:**

> Did a downloader fire right after the first successful Telnet session?

---

### **5. Pivot Detection from “Dumb” Devices**

**Why:** Compromised printers/cameras shouldn’t probe SMB/RDP/SQL.

**Look For:**

* From non-user devices: new outbound to **445/3389/5985/1433**
* **Scanning**: ARP sweeps, `nmap`-like patterns, SYN to many internal IPs
* **Process inventory (where possible)** on the device: shells, `busybox` jobs, reverse shells

**Thought Process:**

> Is something that should only print or stream video now behaving like a recon node?

---

### **6. Persistence Artifacts on Linux/IoT**

**Why:** They’ll survive reboot if they can.

**Look For:**

* **Cron**: `/etc/cron.*` entries with `wget/curl` or arbitrary shell
* **Init/systemd**: `/etc/rc.local`, `/etc/init.d/*`, `/etc/rc*.d/`, `systemctl enable …`
* **BusyBox**: `telnetd -l /bin/sh -p 23` (no auth), or **`chattr +i`** on scripts
* **Hidden dirs**: `/.{random}`, `/usr/bin/.sshd`-looking fakes

**Thought Process:**

> Do startup paths guarantee their payload runs again without a fresh login?

---

### **7. Windows Telnet Misuse (Yes, it happens)**

**Why:** Legacy boxes or someone enabling **Telnet Server** as a backdoor.

**Look For:**

* **EID 4688**: `cmd.exe` spawning `telnet.exe`; **parent** suspicious (PS/LOLBin)
* **Feature toggles** via `dism.exe /online /Enable-Feature:TelnetClient` (or Server)
* **Logons** tied to the Telnet service followed by `bitsadmin`, `powershell -enc`, or SMB beelines

**Thought Process:**

> Did someone light up Telnet on Windows to dodge your SSH/WinRM controls?

---

### **8. Cleanup / Evasion**

**Why:** Smash-and-grab actors tidy up enough to blend.

**Look For:**

* **Linux**: `rm -f` on `/tmp/*`; `> ~/.bash_history`; logs rotated unexpectedly
* **Windows**: **Sysmon EID 23/24** (file delete), stopping **TlntSvr** after use
* Telnet turned **off** post-pivot, leaving you chasing ghosts

**Thought Process:**

> Are artifacts disappearing right after the session ends?

---

## 🧠 Summary

This hunt chains Telnet-specific behaviors that actually matter:

* **Any** 23/2323 traffic is suspicious—baseline it and kill what’s unnecessary
* Service enablement (**TlntSvr/telnetd**) = **persistence**
* Brute-force ➜ quick **downloader chain** (`wget/curl/tftp`) ➜ pivot from “dumb” devices
* Linux/IoT **startup hooks** and BusyBox tricks keep access alive
* Treat Telnet like an **incident until proven otherwise**; replace with SSH, change defaults, segment aggressively, and monitor for re-enablement
