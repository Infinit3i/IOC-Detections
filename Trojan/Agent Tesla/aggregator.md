#TCODES OF INTEREST
[T1048.003  
[T1056.001  
[T1071.003  
[T1087.001  
[T1112  
[T1113  
[T1564.003  
[T1568  

  MITRE ANALYTIC PULLDOWN 
  replace with rules per tcode


  ---

T1048.003

Analytic 1 - Detecting Unencrypted Exfiltration via Command Execution

```SPL
(EventCode=1 OR source="/var/log/audit/audit.log" type="execve")| where (command IN ("ftp", "curl -T", "wget --post-file", "scp", "rsync", "tftp", "base64"))| eval risk_score=case( command IN ("ftp", "scp", "tftp"), 9, command IN ("base64", "gzip", "tar"), 8)| where risk_score >= 8| stats count by _time, host, user, command, risk_score
```

Analytic 1 - Detecting File Access Before Unencrypted Exfiltration
```SPL
(EventCode=11 OR EventCode=4663 OR source="/var/log/audit/audit.log" type="open")| where (file_path IN ("/tmp/", "/var/tmp/", "/home//Downloads/", "C:\Users\*\Documents\exfil") AND file_extension IN ("b64", "tar", "zip"))| eval risk_score=case( file_extension="b64" OR file_extension="tar", 9, file_extension="zip", 8)| where risk_score >= 8| stats count by _time, host, user, file_path, file_extension, risk_score
```


Analytic 1 - Detecting Exfiltration Over Unencrypted Alternative Protocols

```SPL
(EventCode=3 OR source="zeek_conn.log" OR source="firewall_logs")| where (dest_port IN (21, 53, 69, 139, 445, 8080) AND bytes_out > 10000000)| stats count, sum(bytes_out) as total_bytes by _time, host, process, dest_ip, dest_port| where count >= 3 AND total_bytes > 50000000| eval risk_score=case( total_bytes > 100000000, 9, total_bytes > 50000000, 8)| where risk_score >= 8| table host, dest_ip, total_bytes, dest_port, risk_score
```

Analytic 1 - Detecting Encoded Data in Unencrypted Alternative Protocols

```SPL
(EventCode=3 OR source="zeek_http.log" OR source="dns.log")| where (uri_length > 200 OR request_body_length > 5000)| eval encoded_data=if(match(uri, "([A-Za-z0-9+/=]{100,})") OR match(request_body, "([A-Za-z0-9+/=]{100,})"), 1, 0)| where encoded_data=1| stats count by _time, host, user, uri, request_body_length, risk_score| eval risk_score=case( request_body_length > 10000, 9, request_body_length > 5000, 8)| where risk_score >= 8| table host, uri, request_body_length, risk_score
```


---

T1056.001

Monitor for unusual kernel driver installation activity

Monitor for API calls to the SetWindowsHook, GetKeyState, and GetAsyncKeyState and look for common keylogging API calls. API calls alone are not an indicator of keylogging, but may provide behavioral data that is useful when combined with other information such as new files written to disk and unusual processes.

Monitor for changes made to windows registry keys or values for unexpected modifications

---
T1568
Monitor for newly constructed network connections that are sent or received by untrusted hosts.

Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic patterns, anomalous syntax, or structure). Consider correlation with process monitoring and command line to detect anomalous processes execution and command line arguments associated to traffic patterns (e.g. monitor anomalies in use of files that do not normally initiate connections for respective protocol(s)).

Monitor network data for uncommon data flows. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious.

---

T1564.003

Monitor executed commands and arguments that may use hidden windows to conceal malicious activity from the plain sight of users. In Windows, enable and configure event logging and PowerShell logging to check for the hidden window style.

Monitor for changes made to files that may use hidden windows to conceal malicious activity from the plain sight of users. In MacOS, plist files are ASCII text files with a specific format, so they're relatively easy to parse. File monitoring can check for the apple.awt.UIElement or any other suspicious plist tag in plist files and flag them.

Monitor newly executed processes that may use hidden windows to conceal malicious activity from the plain sight of users. For example, monitor suspicious windows explorer execution – such as an additional explorer.exe holding a handle to an unknown desktop – that may be used for hidden malicious activity via hVNC.

Monitor for any attempts to enable scripts running on a system would be considered suspicious. If scripts are not commonly used on a system, but enabled, scripts running out of cycle from patching or other administrator functions are suspicious. Scripts should be captured from the file system when possible to determine their actions and intent.

Monitor for changes in Registry keys such as HKEY_CURRENT_USER\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_PowerShell.exe and HKEY_CURRENT_USER\Console\%SystemRoot%_SysWOW64_WindowsPowerShell_v1.0_PowerShell.exe, especially setting the subkey WindowPosition to a maximum value or the subkeys ScreenBufferSize and WindowSize to 1.


---

T1113

Monitor executed commands and arguments that may attempt to take screen captures of the desktop to gather information over the course of an operation.

Monitoring for screen capture behavior will depend on the method used to obtain data from the operating system and write output files. Detection methods could include collecting information from unusual processes using API calls used to obtain image data, and monitoring for image files written to disk, such as CopyFromScreen, xwd, or screencapture. The sensor data may need to be correlated with other events to identify malicious activity, depending on the legitimacy of this behavior within a given network environment.


---

T1112

Monitor executed commands and arguments for actions that could be taken to change, conceal, and/or delete information in the Registry. The Registry may also be modified through Windows system management tools such as Windows Management Instrumentation and PowerShell, which may require additional logging features to be configured in the operating system to collect necessary information for analysis.

Remote access to the registry can be achieved via Windows API function RegConnectRegistry, command line via reg.exe, or graphically via regedit.exe. All of these behaviors call into the Windows API, which uses the NamedPipe WINREG over SMB to handle the protocol information.

Analytic 1 - Remote Registry  
source="Zeek:" (dest_port="445" AND proto_info.pipe="WINREG") OR (proto_info.function="Create" OR proto_info.function="SetValue")

Monitor for API calls associated with concealing Registry keys, such as Reghide. Inspect and cleanup malicious hidden Registry entries using Native Windows API calls and/or tools such as Autoruns and RegDelNull. Relevant API calls include RegOpenKeyExA, RegCreateKeyExA, RegDeleteKeyExA, RegDeleteValueExA, RegEnumKeyExA, RegEnumValueExA.

Monitor processes and command-line arguments for actions that could be taken to change, conceal, and/or delete information in the Registry (e.g. reg.exe, regedit.exe).

Analytic 1 - Registry Edit with Modification of Userinit, Shell or Notify  
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1") OR  
(source="WinEventLog:Security" EventCode="4688")  
((CommandLine="reg" CommandLine="add" CommandLine="/d") OR ((CommandLine="Set-ItemProperty" OR CommandLine="New-ItemProperty") AND CommandLine="-value"))  
CommandLine="\Microsoft\Windows NT\CurrentVersion\Winlogon" (CommandLine="Userinit" OR CommandLine="Shell" OR CommandLine="Notify")

Analytic 2 - Modification of Default Startup Folder in the Registry Key 'Common Startup'  
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1") OR  
(source="WinEventLog:Security" EventCode="4688")  
(CommandLine="reg" AND CommandLine="add" AND CommandLine="/d") OR  
(CommandLine="Set-ItemProperty" AND CommandLine="-value")  
CommandLine="Common Startup"

Analytic 3 - Registry Edit with Creation of SafeDllSearchMode Key Set to 0  
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1") OR  
(source="WinEventLog:Security" EventCode="4688")  
((CommandLine="reg" CommandLine="add" CommandLine="/d") OR  
(CommandLine="Set-ItemProperty" CommandLine="-value"))  
(CommandLine="00000000" OR CommandLine="0") CommandLine="SafeDllSearchMode")

Monitor for newly constructed registry keys or values, such as HKEY_LOCAL_MACHINE\...\SafeDllSearchMode set to 0.

Analytic 1 - Registry Edit with Creation of SafeDllSearchMode Key Set to 0  
((source="WinEventLog:Security" EventCode="4657")(ObjectValueName="SafeDllSearchMode" value="0")) OR  
((source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13") EventType="SetValue" TargetObject="*SafeDllSearchMode" Details="DWORD (0x00000000)")

Monitor for unexpected deletion of windows registry keys.

Monitor for changes made to registry keys or values. Enable Registry Auditing on specific keys to produce alertable events (Event ID 4657).

Analytic 1 - Registry Edit with Modification of Userinit, Shell or Notify  
source="WinEventLog:Security" EventCode="4657" (ObjectValueName="Userinit" OR ObjectValueName="Shell" OR ObjectValueName="Notify") OR  
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" (TargetObject="Userinit" OR TargetObject="Shell" OR TargetObject="*Notify")

Analytic 2 - Modification of Default Startup Folder in the Registry Key 'Common Startup'  
(source="WinEventLog:Security" EventCode="4657" ObjectValueName="Common Startup") OR  
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" TargetObject="*Common Startup")


---

T1087.001

Monitor for execution of commands and arguments associated with enumeration or information gathering of local accounts and groups such as net user, net account, net localgroup, Get-LocalUser, dscl, and esxcli system accounts list.

Monitor access to file resources that contain local accounts and groups information such as /etc/passwd, /Users directories, and the Windows SAM database. If access requires high privileges, look for non-admin objects attempting to access restricted file resources.

Monitor for logging that may suggest a list of available groups and/or their associated settings has been extracted, such as Windows EID 4798 and 4799.

Monitor for API calls (such as NetUserEnum()) that may attempt to gather local accounts information such as type of user, privileges and groups.

Monitor for processes that can be used to enumerate user accounts and groups such as net.exe and net1.exe, especially when executed in quick succession. Information may also be acquired through Windows system management tools such as WMI and PowerShell.

Analytic 1 - Net Discovery Commands  
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1") OR  
(source="WinEventLog:Security" EventCode="4688")  
Image="net.exe" OR Image="net1.exe"


---
T1071.003

Monitor and analyze traffic patterns and packet inspection associated to protocol(s), leveraging SSL/TLS inspection for encrypted traffic, that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic patterns, anomalous syntax, or structure). Consider correlation with process monitoring and command line to detect anomalous processes execution and command line arguments associated to traffic patterns (e.g. monitor anomalies in use of files that do not normally initiate connections for respective protocol(s)).

Monitor and analyze traffic flows that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, or gratuitous or anomalous traffic patterns). Consider correlation with process monitoring and command line to detect anomalous processes execution and command line arguments associated to traffic patterns (e.g. monitor anomalies in use of files that do not normally initiate connections for respective protocol(s)).

