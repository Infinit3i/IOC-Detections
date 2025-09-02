Roundcube is ≤ 1.6.10 (or < 1.5.10), assume it’s exploitable **post-auth** via PHP object deserialization in `program/actions/settings/upload.php` and hunt like it’s already been used. The fix landed in 1.6.11/1.5.10 with strict `_from` sanitization; anything older is fair game. ([roundcube.net][1], [GitHub][2], [NVD][3])

---

# 🎯 Objective

Catch active exploitation of **CVE-2025-49113** (Roundcube post-auth RCE) and resulting post-exploitation on the webmail host. ([NVD][3], [OffSec][4])

> Root cause: `_from` parameter lets an attacker corrupt the session and feed a gadget chain to PHP, leading to code exec from the Roundcube/PHP worker. Patch validates `_from` against `^[\\w.-]+$`. ([GitHub][2])

---

# ✅ Hypothesis

> “An authenticated mailbox user abused the vulnerable upload handler to deserialize a crafted object and execute commands (via PHP), then dropped tools or pivoted from the Roundcube host.”

---

# 🧱 Tactics to Focus On

1. **Initial foothold (post-auth)** via Roundcube UI; 2) **Execution** from `php-fpm/apache2` → shell; 3) **Staging** in `/tmp` or Roundcube dirs; 4) **Credential/Data access** (DB/mailstore); 5) **Lateral movement** from the webmail host.

---

# 🔍 Hunt Steps (True Threat Hunt Chain)

### 1) Find exploit traffic to the vulnerable endpoint

**Why:** Exploit path is stable: `program/actions/settings/upload.php` with `_from=` (often `edit-…`) and weird punctuation.
**Look for (HTTP/Proxy/WAF logs):**

* `POST` to `/program/actions/settings/upload.php` with query `_task=settings&_action=upload&_from=...`
* Multipart form with `_file[]` and odd `filename=` values (session junk in name).
* `_from` containing characters outside `[\w\.-]` (e.g., `!`, `;`, quotes).
  **Splunk (Apache/Nginx)**:

```spl
index=web (sourcetype=apache:access OR sourcetype=nginx:access) uri_path="/program/actions/settings/upload.php" method=POST
\n| rex field=uri_query "_from=(?<from>[^&]+)"
\n| where NOT match(from, "^[\\w\\.-]+$")
\n| stats count AS hits, dc(src_ip) AS srcs, values(http_user_agent) AS ua BY src_ip, from, uri_query
```

### 2) Tie it to a signed-in mailbox (it’s post-auth)

**Why:** Valid creds are required.
**Look for:** Same `src_ip`/session hitting `/?_task=login` then the upload path minutes later; IMAP/SMTP auth from new IPs belonging to that user.
**Splunk (Roundcube/IMAP logs)**:

```spl
index=mail (sourcetype=roundcube:error OR sourcetype=roundcube:auth OR sourcetype=imap:dovecot)
\n| transaction user maxspan=15m
\n| search (uri_path="/program/actions/settings/upload.php" OR message="login" OR "Authenticated user")
\n| table _time user src_ip uri_path message
```

### 3) Catch process spawn from PHP workers

**Why:** Successful RCE typically spawns `sh`, `bash`, `wget`, `curl`, `perl`, `python`, `php -r`, `nc`.
**Linux EDR/audit/Sysmon-for-Linux:** parent = `php-fpm` or `apache2`/`httpd` → child shell.
**Splunk (Sysmon-Linux / Auditd)**:

```spl
index=os (sourcetype=sysmon:linux OR sourcetype=auditd)
\n| search (ParentImage="*php-fpm*" OR ParentImage="*apache2*" OR exe="/usr/sbin/apache2" OR exe="/usr/sbin/httpd")
\n| search (Image="*/sh" OR Image="*/bash" OR Image="*/curl" OR Image="*/wget" OR Image="*/nc" OR Image="*/python*" OR CommandLine="* | sh*")
\n| stats earliest(_time) AS first_seen latest(_time) AS last_seen values(CommandLine) BY host, user, ParentImage, Image
```

### 4) Spot filesystem staging and webshell drops

**Why:** Attackers write to `/tmp`, `logs/`, `plugins/`, or webroot; names often random.
**Look for:** New `.php` in Roundcube dirs; executables/chmods in `/tmp`; unexpected ownership under `www-data`.
**Splunk (FIM/audit logs):**

```spl
index=os sourcetype=auditd (file IN ("/var/www/html/roundcube/*","/usr/share/roundcube/*","/tmp/*"))
\n| search (file="*.php" OR file="*.sh" OR file="*.so" OR file="*.pl" OR file="*.py")
\n| stats min(_time) AS first_seen values(syscall) AS ops BY file, host, uid, auid
```

### 5) Network egress right after the POST

**Why:** Common behavior is immediate fetch & run (curl/wget/tftp).
**Look for:** Outbound HTTP/TCP from the Roundcube host within 0–120s of the suspicious POST.
**Splunk (Netflow/Zeek):**

```spl
(index=web uri_path="/program/actions/settings/upload.php" method=POST)
\n| stats latest(_time) AS t by src_ip
\n| join src_ip [ search index=net sourcetype=zeek:http OR sourcetype=netflow dest_ip!=internal ]
\n| eval delta= _time - t
\n| where delta>=0 AND delta<=120
\n| table t _time src_ip dest_ip uri dest_host user_agent status
```

### 6) Roundcube app logs (pre vs post patch)

**Pre-patch success often leaves little; post-patch you’ll see explicit rejects.**

* Post-patch error text: `The URL parameter "_from" contains disallowed characters...` → treat as **blocked exploit attempt** (investigate the account/IP). ([GitHub][2])

### 7) Lateral movement from the webmail host

**Why:** Once in, actors pivot into DB, file shares, or internal apps.
**Look for:** New connections from the webmail host to 3306/5432 (mail DB), 445/389/636/5985, or cloud metadata services; credential dumping from the mail host.

---

# 🚑 Triage & Containment (do this now)

1. **Version check** on every Roundcube node; anything below **1.6.11 / 1.5.10** is vulnerable—**patch immediately**. ([roundcube.net][1])
2. **Account pivot check**: users who hit the upload handler → force rotate passwords & revoke active sessions/tokens.
3. **Host scope**: if you see PHP-spawned shells, **isolate** host, image it, and sweep for webshells in Roundcube dirs and `/tmp`.
4. **DB/mailstore review**: dump access from webmail account? Pull logs and compare to baseline.

---

# 🧪 Optional detections (additions)

**Zeek HTTP (query idea):** `uri contains "program/actions/settings/upload.php" AND method=POST AND id_resp_p in {80,443}` with `user_agent` outliers.

**Suricata (indicative HTTP sig, tune to reduce FPs):**

```
alert http any any -> $HOME_NET any (msg:"Roundcube CVE-2025-49113 exploit attempt";
flow:to_server,established; http.method; content:"POST"; http.uri;
content:"/program/actions/settings/upload.php"; http.uri; nocase;
pcre:"/_from=.*[^\\w\\.-]/Ui"; classtype:web-application-attack; sid:925113; rev:1;)
```

(Heuristic: flags non-simple `_from` to that path.)

---

# 🛠 Mitigation & Hardening

* **Upgrade** to **1.6.11 / 1.5.10** (or newer) everywhere; vendor bundles (cPanel/Plesk) may lag—verify manually. ([roundcube.net][1])
* **WAF rule** temporarily blocking `POST /program/actions/settings/upload.php` or rejecting `_from` outside `^[\w\.-]+$` until all nodes are patched.
* **Least privilege**: run PHP/FPM under a low-priv user; no shell, no DB superuser; mount webroot `noexec` where possible.
* **Log & monitor**: keep Roundcube error/access logs, PHP-FPM slow/error logs, and command audit enabled.
* **Hunt regularly**: script a daily search for that endpoint + weird `_from` and PHP-spawned shells.

---

# 📚 Sources (for your IR report)

* Roundcube security update notice (fix in **1.6.11/1.5.10**). ([roundcube.net][1])
* Patch commit adding `_from` validation & `is_simple_string()`. ([GitHub][2])
* NVD summary of CVE-2025-49113 (scope/versions). ([NVD][3])
* OffSec write-up (background and impact). ([OffSec][4])
* Deep technical analysis / PoC context by FearsOff (for defenders). ([FearsOff][5], [GitHub][6])

If you want, I’ll convert this into a Splunk saved-search pack (web, host, and Zeek detections) tailored to your field names.

[1]: https://roundcube.net/news/2025/06/01/security-updates-1.6.11-and-1.5.10 "Security updates 1.6.11 and 1.5.10 released"
[2]: https://github.com/roundcube/roundcubemail/commit/0376f69e958a8fef7f6f09e352c541b4e7729c4d "Validate URL parameter in upload code (#9866) · roundcube/roundcubemail@0376f69 · GitHub"
[3]: https://nvd.nist.gov/vuln/detail/CVE-2025-49113?utm_source=chatgpt.com "NVD - CVE-2025-49113"
[4]: https://www.offsec.com/blog/cve-2025-49113/?utm_source=chatgpt.com "CVE‑2025‑49113 – Post‑Auth Remote Code Execution in Roundcube via PHP ..."
[5]: https://fearsoff.org/research/roundcube?utm_source=chatgpt.com "Roundcube ≤ 1.6.10 Post-Auth RCE via PHP Object Deserialization [CVE ..."
[6]: https://github.com/fearsoff-org/CVE-2025-49113/blob/main/CVE-2025-49113.php?utm_source=chatgpt.com "CVE-2025-49113/CVE-2025-49113.php at main · fearsoff-org/CVE ... - GitHub"
