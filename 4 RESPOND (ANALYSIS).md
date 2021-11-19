# 4 RESPOND (ANALYSIS)

**LIVE TRIAGE - WINDOWS**

## SYSTEM INFORMATION
---
```
C:\> echo %DATE% %TIME%
C:\> hostname
C:\> systeminfo
C:\> systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
C:\> wmic csproduct get name
C:\> wmic bios get serialnumber
C:\> wmic computersystem list brief
C:\> psinfo -accepteula -s -h -d 
```

[SYSTEM INFORMATION](https://docs.microsoft.com/en-au/sysinternals/downloads/psinfo)
---

## USER INFORMATION
---
```
C:\> whoami
C:\> net users
C:\> net localgroup administrators
C:\> net group administrators
C:\> wmic rdtoggle list
C:\> wmic useraccount list
C:\> wmic group list
C:\> wmic netlogin get name, lastlogon,badpasswordcount
C:\> wmic netclient list brief
C:\> doskey /history> history.txt
```

---

## NETWORK INFORMATION
---
```
C:\> netstat -e
C:\> netstat -naob
C:\> netstat -nr
C:\> netstat -vb
C:\> nbtstat -s
C:\> route print
C:\> arp -a
C:\> ipconfig /displaydns
C:\> netsh winhttp show proxy
C:\> ipconfig /allcompartments /all
C:\> netsh wlan show interfaces
C:\> netsh wlan show all 

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSettings"

C:\> type %SYSTEMROOT%\system32\drivers\etc\hosts
C:\> wmic nicconfig get descriptions,IPaddress,MACaddress
C:\> wmic netuse get name,username,connectiontype, localname
```
---

## SERVICE INFORMATION
---
```
C:\> at
C:\> tasklist
C:\> task list /SVC
C:\> tasklist /SVC /fi "imagename eq svchost.exe"
C:\> schtasks
C:\> net start
C:\> sc query
C:\> wmic service list brief | findstr "Running"
C:\> wmic service list config
C:\> wmic process list brief
C:\> wmic process list status
C:\> wmic process list memory
C:\> wmic job list brief

PS C:\> Get-Service | Where-Object { $_.Status -eq "running" } 
```

**List of all processes and then all loaded modules:**
```
PS C:\> Get-Process | select modules | Foreach-Object{$_.modules} 
```
---

## POLICY, PATCH AND SETTINGS INFORMATION
---
```
C:\> set
C:\> gpresult /r
C:\> gpresult /z > <OUTPUT FILE NAME>.txt
C:\> gpresult /H report.html /F
C:\> wmic qfe 
```

**List GPO software installed:**
```
C:\> reg query "HKLM\Software\Microsoft\Windows\Current Version\Group Policy\AppMgmt" 
```
---

## AUTORUN AND AUTOLOAD INFORMATION
---
**Startup information:**
```
C:\> wmic startup list full
C:\> wmic ntdomain list brief 
```

**View directory contents of startup folder:**
```
Todo
```
---