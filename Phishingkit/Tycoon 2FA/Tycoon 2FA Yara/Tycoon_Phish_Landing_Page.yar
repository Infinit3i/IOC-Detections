rule Tycoon_Phish_Landing_Page {
  meta:
    description = "Tycoon_Phish_Landing_Page"
  strings:
   $obf_str1 = "emailcheck" ascii
   $obf_str2 = "ccturnhtml" ascii
   $obf_str3 = "ccelehtml" ascii
   $obf_str4 = "cchtml" ascii
   $obf_str5 = "bchtml" ascii
   $obf_str6 = "atob" ascii
   $obf_str7 = "String.fromCharCode" ascii
   $obf_str8 = "document.write" ascii
   $plain_str1 = /language=\"Javascript\"/
   $plain_str2 = /src=\"http.{2,99}\/myscr\d{4,6}\.js\"/
  condition:
   (all of ($obf_str*)) or (all of ($plain_str*) and filesize < 250)
}