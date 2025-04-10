
#bad example rule i need to work on

index=win_sysmon EventCode=10 ParentUser="NT AUTHORITY\\SYSTEM" process_name=*
| stats count by _time, ParentUser, ParentImage, process_name, EventCode 
| where ParentImage!="C:\\Windows\\explorer.exe" AND ParentImage!="C:\\Windows\\System32\\cmd.exe" 
| rename process_name as ProcessName 
| table _time, ParentUser, ParentImage, ProcessName, EventCode
