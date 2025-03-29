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

