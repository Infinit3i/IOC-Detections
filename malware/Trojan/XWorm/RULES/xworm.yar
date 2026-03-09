rule Windows_Trojan_Xworm_732e6c12 {
meta:
    author = "Elastic Security"
    id = "732e6c12-9ee0-4d04-a6e4-9eef874e2716"
    fingerprint = "afbef8e590105e16bbd87bd726f4a3391cd6a4489f7a4255ba78a3af761ad2f0"
    creation_date = "2023-04-03"
    last_modified = "2023-04-03"
    os = "Windows"
    arch = "x86"
    category_type = "Trojan"
    family = "Xworm"
    threat_name = "Windows.Trojan.Xworm"
    source = "Manual"
    maturity = "Diagnostic"
    reference_sample = "bf5ea8d5fd573abb86de0f27e64df194e7f9efbaadd5063dee8ff9c5c3baeaa2"
    scan_type = "File, Memory"
    severity = 100

strings:
    $str1 = "startsp" ascii wide fullword
    $str2 = "injRun" ascii wide fullword
    $str3 = "getinfo" ascii wide fullword
    $str4 = "Xinfo" ascii wide fullword
    $str5 = "openhide" ascii wide fullword
    $str6 = "WScript.Shell" ascii wide fullword
    $str7 = "hidefolderfile" ascii wide fullword
condition:
    all of them
}