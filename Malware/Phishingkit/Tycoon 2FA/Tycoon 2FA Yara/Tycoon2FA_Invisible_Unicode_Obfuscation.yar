rule Tycoon2FA_Invisible_Unicode_Obfuscation {
  meta:
    description = "Detects repeated use of invisible Unicode characters for binary obfuscation in Tycoon 2FA kit"
    date = "2025-04-01"
    author = "Trustwave SpiderLabs"
  strings:
    $hangul_filler    = "\xE3\x85\xA4"    // Hangul Filler (binary 1)
    $halfwidth_filler = "\xEF\xBE\xA0"    // Halfwidth Hangul Filler (binary 0)
    $str_proxy        = "new Proxy" ascii nocase
    $str_eval         = "eval" ascii nocase
    $str_map          = "map" ascii nocase
    $str_join         = "join" ascii nocase
    $str_fromchar     = "String.fromCharCode" ascii nocase
    $str_parseInt     = "parseInt" ascii nocase
  condition:
    (#hangul_filler > 50 and #halfwidth_filler > 50) and all of ($str_*)
}
