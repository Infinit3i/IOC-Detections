
```
# ─────────────────────────────────────────────
# 🛡️ AgentTesla C2 Communication Detection
# ─────────────────────────────────────────────

# Rule 1: Detect response from ams.stablehost.com (sets flowbit)
alert tcp any 587 -> any any (
    msg:"Data Exfiltration to AgentTesla C2 — Communication with ams.stablehost.com";
    flow:to_client, established;
    content:"|61 6d 73 2e 73 74 61 62 6c 65 68 6f 73 74 2e 63 6f 6d|";
    flowbits:set,ams_stablehost_com_detected;
    flowbits:noalert;
    sid:1000001;
)

# Rule 2: Detect outbound connection to mail.knoow.net if flowbit is set
alert tcp any any -> any 587 (
    msg:"Data Exfiltration to AgentTesla C2 — Communication with mail.knoow.net and ams.stablehost.com";
    flow:to_server, established;
    content:"|6d 61 69 6c 2e 6b 6e 6f 6f 77 2e 6e 65 74|";
    flowbits:isset,ams_stablehost_com_detected;
    sid:1000002;
)

# ─────────────────────────────────────────────
# 🧰 Suspicious Ingress Tool Transfer Detection
# ─────────────────────────────────────────────

# Rule 3: Detect outbound HTTPS connection to didaktik-labor.de
alert tcp any any -> any 443 (
    msg:"Suspicious for Ingress Tool Transfer — Communication with didaktik-labor.de";
    flow:to_server, established;
    content:"|64 69 64 61 6b 74 69 6b 2d 6c 61 62 6f 72 2e 64 65|";
    sid:1000000;
)
```
