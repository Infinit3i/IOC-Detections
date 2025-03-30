rule M_AES_Encrypted_payload {
  meta:
    author = "Mandiant"
    description = "This rule is desgined to detect on events that 
exhibits indicators of utilizing AES encryption for payload obfuscation."
    target_entity = "Process"
  strings:
    $a = /(\$\w+\.Key(\s|)=((\s|)(\w+|));|\$\w+\.Key(\s|)=(\s|)\w+\('\w+'\);)/
    $b = /\$\w+\.IV/
    $c = /System\.Security\.Cryptography\.(AesManaged|Aes)/
  condition:
    all of them
}

rule M_Downloader_PEAKLIGHT_1 {
    meta:
    	mandiant_rule_id = "e0abae27-0816-446f-9475-1987ccbb1bc0"
        author = "Mandiant"
        category = "Malware"
        description = "This rule is designed to detect on events related to peaklight. 
PEAKLIGHT is an obfuscated PowerShell-based downloader which checks for 
the presence of hard-coded filenames and downloads files from a remote CDN 
if the files are not present."
        family = "Peaklight"
        platform = "Windows"
    strings:
        $str1 = /function\s{1,16}\w{1,32}\(\$\w{1,32},\s{1,4}\$\w{1,32}\)\
{\[IO\.File\]::WriteAllBytes\(\$\w{1,32},\s{1,4}\$\w{1,32}\)\}/ ascii wide 
        $str2 = /Expand-Archive\s{1,16}-Path\s{1,16}\$\w{1,32}\
s{1,16}-DestinationPath/ ascii wide
        $str3 = /\(\w{1,32}\s{1,4}@\((\d{3,6},){3,12}/ ascii wide
        $str4 = ".DownloadData(" ascii wide
        $str5 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12" ascii wide
        $str6 = /\.EndsWith\(((["']\.zip["'])|(\(\w{1,32}\s{1,16}@\((\d{3,6},){3}\d{3,6}\)\)))/ ascii wide
        $str7 = "Add -Type -Assembly System.IO.Compression.FileSystem" ascii wide
	$str8 = "[IO.Compression.ZipFile]::OpenRead"
    condition:
	    4 of them and filesize < 10KB         
}

rule loader_fakebat_initial_powershell_may24 {
    meta:
   	 malware = "FakeBat"
   	 description = "Finds FakeBat initial PowerShell script downloading and executing the next-stage payload."
   	 source = "Sekoia.io"
   	 classification = "TLP:WHITE"

    strings:
   	 $str01 = "='http" wide
   	 $str02 = "=(iwr -Uri $" wide
   	 $str03 = " -UserAgent $" wide
   	 $str04 = " -UseBasicParsing).Content; iex $" wide

    condition:
    	3 of ($str*) and
    	filesize < 1KB
}

rule loader_fakebat_powershell_fingerprint_may24 {
   meta:
       malware = "FakeBat"
       description = "Finds FakeBat PowerShell script fingerprinting the infected host."
       source = "Sekoia.io"
       classification = "TLP:WHITE"

   strings:
       $str01 = "Get-WmiObject Win32_ComputerSystem" ascii
       $str02 = "-Class AntiVirusProduct" ascii
       $str03 = "status = \"start\"" ascii
       $str04 = " | ConvertTo-Json" ascii
       $str05 = ".FromXmlString(" ascii
       $str06 = " = Invoke-RestMethod -Uri " ascii
       $str07 = ".Exception.Response.StatusCode -eq 'ServiceUnavailable'" ascii
       $str08 = "Invoke-WebRequest -Uri $url -OutFile " ascii
       $str09 = "--batch --yes --passphrase-fd" ascii
       $str10 = "--decrypt --output" ascii
       $str11 = "Invoke-Expression \"tar --extract --file=" ascii

   condition:
       7 of ($str*) and
       filesize < 10KB
}


import "vt"

rule infostealer_win_stealc_behaviour {
	meta:
		malware = "Stealc"
		description = "Find Stealc sample based characteristic behaviors"
		source = "SEKOIA.IO"
		reference = "https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/"
		classification = "TLP:CLEAR"
		hash = "3feecb6e1f0296b7a9cb99e9cde0469c98bd96faed0beda76998893fbdeb9411"

	condition:
        for any cmd in vt.behaviour.command_executions : (
        	cmd contains "\\*.dll"
        ) and
        for any cmd in vt.behaviour.command_executions : (
        	cmd contains "/c timeout /t 5 & del /f /q"
        ) and
		for any c in vt.behaviour.http_conversations : (
			c.url contains ".php"
		)
}


rule infostealer_win_stealc_standalone {
    meta:
        malware = "Stealc"
        description = "Find standalone Stealc sample based on decryption routine or characteristic strings"
        source = "SEKOIA.IO"
        reference = "https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/"
        classification = "TLP:CLEAR"
        hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"

    strings:
		$dec = { 55 8b ec 8b 4d ?? 83 ec 0c 56 57 e8 ?? ?? ?? ?? 6a 03 33 d2 8b f8 59 f7 f1 8b c7 85 d2 74 04 } //deobfuscation function 

        $str01 = "------" ascii
        $str02 = "Network Info:" ascii
        $str03 = "- IP: IP?" ascii
        $str04 = "- Country: ISO?" ascii
        $str05 = "- Display Resolution:" ascii
        $str06 = "User Agents:" ascii
        $str07 = "%s\\%s\\%s" ascii

    condition:
        uint16(0) == 0x5A4D and ($dec or 5 of ($str*))
}

rule NetVineSigned {
   meta:
      description = "Detection rule for NetVineSigned.exe malware"
      author = "BGD e-GOV CIRT CTI Team"
      reference = "Internal Threat Intelligence Report"
      date = "2024-10-08"
      hash1 = "cca0ccec702392583c6e1356a3ff1df0d20d5837c3cd317464185e8780121ab1" // SHA-256 hash of NetVineSigned.exe

   strings:
      $s1 = "rundll32.exe shell32.dll,Control_RunDLL MMSys.cpl" fullword ascii
      $s2 = "#Incompatible version of WINSOCK.DLL" fullword ascii
      $s3 = ";http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.p7c0#" fullword ascii
      $s4 = "https://www.ssuiteoffice.com" fullword ascii
      $s5 = "ssuiteoffice.com" fullword ascii
      $s6 = "http://www.netmastersllc.com" fullword ascii
      $s7 = ";http://crl.sectigo.com/SectigoPublicTimeStampingRootR46.crl0|" fullword ascii
      $s8 = "visit us at ssuiteoffice.com" fullword wide
      $s9 = "TLOGINDIALOG" fullword wide
      $s10 = "NetVine - HeaderFooterForm" fullword ascii
      $s11 = "https://sectigo.com/CPS0" fullword ascii
      $s12 = "AddressList.dat" fullword ascii
      $s13 = "Error setting %s.Count8Listbox (%s) style must be virtual in order to set Count\"Unable to find a Table Of Contents" fullword wide
      $s14 = ":http://secure.globalsign.com/cacert/codesigningrootr45.crt0A" fullword ascii
      $s15 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl05" fullword ascii
      $s16 = "-http://ocsp.globalsign.com/codesigningrootr450F" fullword ascii
      $s17 = "9http://crt.sectigo.com/SectigoPublicTimeStampingCAR36.crt0#" fullword ascii
      $s18 = "9http://crl.sectigo.com/SectigoPublicTimeStampingCAR36.crl0z" fullword ascii
      $s19 = "0http://crl.globalsign.com/codesigningrootr45.crl0U" fullword ascii
      $s20 = "GIF encoded data is corrupt!GIF code size not in range 2 to 9,Wrong number of colors; must be a power of 2\"Unrecognized extensi" wide

   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      8 of them
}

rule LummaC2 {

    meta:
        author = "RussianPanda"
        description = "LummaC2 Detection"

    strings:
        $p1="lid=%s&j=%s&ver"
        $p2= {89 ca 83 e2 03 8a 54 14 08 32 54 0d 04}

    condition:
        all of them and filesize <= 500KB
}


rule win_lumma_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.lumma."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 53 ff767c ff7678 ff7644 }
            // n = 4, score = 1100
            //   53                   | push                ebx
            //   ff767c               | push                dword ptr [esi + 0x7c]
            //   ff7678               | push                dword ptr [esi + 0x78]
            //   ff7644               | push                dword ptr [esi + 0x44]

        $sequence_1 = { ff7608 ff7044 ff503c 83c414 }
            // n = 4, score = 1100
            //   ff7608               | push                dword ptr [esi + 8]
            //   ff7044               | push                dword ptr [eax + 0x44]
            //   ff503c               | call                dword ptr [eax + 0x3c]
            //   83c414               | add                 esp, 0x14

        $sequence_2 = { ff7134 ff5130 83c410 85c0 }
            // n = 4, score = 1100
            //   ff7134               | push                dword ptr [ecx + 0x34]
            //   ff5130               | call                dword ptr [ecx + 0x30]
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax

        $sequence_3 = { e8???????? 833800 740a e8???????? 833822 }
            // n = 5, score = 1000
            //   e8????????           |                     
            //   833800               | cmp                 dword ptr [eax], 0
            //   740a                 | je                  0xc
            //   e8????????           |                     
            //   833822               | cmp                 dword ptr [eax], 0x22

        $sequence_4 = { 894610 8b461c c1e002 50 }
            // n = 4, score = 1000
            //   894610               | mov                 dword ptr [esi + 0x10], eax
            //   8b461c               | mov                 eax, dword ptr [esi + 0x1c]
            //   c1e002               | shl                 eax, 2
            //   50                   | push                eax

        $sequence_5 = { ff770c ff37 ff7134 ff5130 }
            // n = 4, score = 1000
            //   ff770c               | push                dword ptr [edi + 0xc]
            //   ff37                 | push                dword ptr [edi]
            //   ff7134               | push                dword ptr [ecx + 0x34]
            //   ff5130               | call                dword ptr [ecx + 0x30]

        $sequence_6 = { 83c410 85c0 7407 8907 }
            // n = 4, score = 1000
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   8907                 | mov                 dword ptr [edi], eax

        $sequence_7 = { ff7678 ff7644 ff563c 83c414 }
            // n = 4, score = 1000
            //   ff7678               | push                dword ptr [esi + 0x78]
            //   ff7644               | push                dword ptr [esi + 0x44]
            //   ff563c               | call                dword ptr [esi + 0x3c]
            //   83c414               | add                 esp, 0x14

        $sequence_8 = { 017e78 83567c00 017e68 83566c00 }
            // n = 4, score = 800
            //   017e78               | add                 dword ptr [esi + 0x78], edi
            //   83567c00             | adc                 dword ptr [esi + 0x7c], 0
            //   017e68               | add                 dword ptr [esi + 0x68], edi
            //   83566c00             | adc                 dword ptr [esi + 0x6c], 0

        $sequence_9 = { 83c40c 6a02 6804010000 e8???????? }
            // n = 4, score = 800
            //   83c40c               | add                 esp, 0xc
            //   6a02                 | push                2
            //   6804010000           | push                0x104
            //   e8????????           |                     

        $sequence_10 = { 8d8672920300 ff7604 57 50 }
            // n = 4, score = 800
            //   8d8672920300         | lea                 eax, [esi + 0x39272]
            //   ff7604               | push                dword ptr [esi + 4]
            //   57                   | push                edi
            //   50                   | push                eax

        $sequence_11 = { ff7034 ff5030 83c410 85c0 }
            // n = 4, score = 800
            //   ff7034               | push                dword ptr [eax + 0x34]
            //   ff5030               | call                dword ptr [eax + 0x30]
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax

        $sequence_12 = { 41 5a cb 55 89e5 }
            // n = 5, score = 700
            //   41                   | inc                 ecx
            //   5a                   | pop                 edx
            //   cb                   | retf                
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp

        $sequence_13 = { e8???????? 83c40c 017e58 297e5c 03be8c000000 }
            // n = 5, score = 700
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   017e58               | add                 dword ptr [esi + 0x58], edi
            //   297e5c               | sub                 dword ptr [esi + 0x5c], edi
            //   03be8c000000         | add                 edi, dword ptr [esi + 0x8c]

        $sequence_14 = { 59 41 58 5a 59 41 5a }
            // n = 7, score = 700
            //   59                   | pop                 ecx
            //   41                   | inc                 ecx
            //   58                   | pop                 eax
            //   5a                   | pop                 edx
            //   59                   | pop                 ecx
            //   41                   | inc                 ecx
            //   5a                   | pop                 edx

        $sequence_15 = { f6460a04 7507 837e3c30 0f92c0 }
            // n = 4, score = 700
            //   f6460a04             | test                byte ptr [esi + 0xa], 4
            //   7507                 | jne                 9
            //   837e3c30             | cmp                 dword ptr [esi + 0x3c], 0x30
            //   0f92c0               | setb                al

        $sequence_16 = { c70000000000 85c9 7406 c70100000000 c7466cfeffffff b8feffffff 5e }
            // n = 7, score = 700
            //   c70000000000         | mov                 dword ptr [eax], 0
            //   85c9                 | test                ecx, ecx
            //   7406                 | je                  8
            //   c70100000000         | mov                 dword ptr [ecx], 0
            //   c7466cfeffffff       | mov                 dword ptr [esi + 0x6c], 0xfffffffe
            //   b8feffffff           | mov                 eax, 0xfffffffe
            //   5e                   | pop                 esi

        $sequence_17 = { e8???????? 83c40c 019e8c000000 39ef }
            // n = 4, score = 700
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   019e8c000000         | add                 dword ptr [esi + 0x8c], ebx
            //   39ef                 | cmp                 edi, ebp

    condition:
        7 of them and filesize < 1115136
}

rule infostealer_win_lumma_strings_sept23 {
    meta:
        version = "1.0"
        description = "Finds Lumma samples based on the specific strings"
        author = "Sekoia.io"
        creation_date = "2023-09-14"
        modification_date = "2023-10-31"
        id = "45900760-c10d-40c0-a49a-c66358a8a66a"
        classification = "TLP:CLEAR"
        
    strings:
        $str10 = "CryptStringToBinaryA" ascii
        $str11 = "WinHttpQueryDataAvailable" ascii
        $str12 = "GetComputerNameExA" ascii
        $str13 = "GetCurrentHwProfileW" ascii
        $str14 = "ntdll.dll" wide
        //$str15 = "%appdata%\\Thunderbird\\Profiles" wide
        $str16 = "minkernel\\crts\\ucrt\\inc\\corecrt_internal_strtox.h" wide
        $str17 = "xxxxxxxxxxx" ascii
        
    condition:
        uint16(0)==0x5A4D and all of them
}
