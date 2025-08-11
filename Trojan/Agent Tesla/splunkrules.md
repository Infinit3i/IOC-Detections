#editing these presently
#Suspicious use of credential-harvesting tools
```spl
index=main OR index=endpoint sourcetype="WinEventLog:Security"
(Process_Name="powershell.exe" OR Process_Name="regsvr32.exe" OR Process_Name="mshta.exe")
(CommandLine="*FromBase64String*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*System.Net.Mail*")
| stats count by _time, host, user, Process_Name, CommandLine
| where count > 5
```


#Unusual outbound data exfiltration via SMTP or FTP
```spl
index=network sourcetype="Stream:SMTP" OR sourcetype="Stream:FTP"
(src_ip="10.0.0.0/8" OR src_ip="192.168.0.0/16") 
| stats count by src_ip, dest_ip, dest_port, bytes_out
| where bytes_out > 500000
```
