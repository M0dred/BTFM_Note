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


**MALWARE ANALYSIS**

## STATIC ANALYSIS BASICS
---
**Mount live Sysinternats toots drive:**
```
\\live.sysinternals.com\tools
```

**Signature check of dll, exe files:**

[Signature check](https://docs.microsoft.com/en-au/sysinternals/downloads/sigcheck)
```
C:\> sigcheck.exe -u -e C:\<DIRECTORY>
```

**Send to VirusTotal:**
```
C:\> sigcheck.exe -vt <SUSPICIOUS FILE NAME>
```

**Windows PE Analysis:
View Hex and ASCI of PE{exe or any file), with optional -n first 500 bytes:**
```
# hexdump -C -n 500 <SUSPICIOUS FILE NAME>
# od -x somefile.exe
# xxd somefile.exe
```

**In Windows using debug tool {works for .java files too):** 
```
C:\> debug <SUSPICIOUS FILE NAME>
> -d (just type d and get a page at a time of hex)
> -q (quit debugger) 
```

**PE Fite Compile Date/Time pert script below (Windows PE only script).**

[Perl Download](https://www.perl.org/get.html) 
[Perl Getting compile time out of Windows binary (exe and dll) files](https://www.perlmonks.org/bare/?node_id=484287)


**View strings within PE and optional string length -n option:**
**Using stings in Linux:**
```
# strings -n 10 <SUSPICIOUS FILE NAME>
```

[Using Strings](https://technet.microsoft.com/en-us/sysinternals/strings.aspx)

**Using strings in Windows:**
```
C:\> strings <SUSPICIOUS FILE NAME> 
```

**Find Malware in memory dump using Volatility and Windows7SPFix64 profile:**

[Volatility](https://github.com/volatilityfoundation/volatility)

```
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -profile=Win7SPFix64 malfind -D /<OUTPUT DUMP DIRECTORY>
```

**Find Malware with PID in memory dump using Volatility:**
```
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -profile=Win7SPFix64 malfind -p <PID #> -D /<OUTPUT DUMP DIRECTORY>
```

**Find suspicious processes using Volatility:**
```
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -profile=Win7SPFix64 pslist
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -profile=Win7SPFix64 pstree
```

**Find suspicious dlls using Volatility:**
```
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -profile=Win7SPFix64 dlllist
# python vol.py -f <MEMORY DUMP FILE NAME>.raw -profile=Win7SPFix64 dlldump -D /<OUTPUT DUMP DIRECTORY> 
```

**Malware analysis parsing Tool:**

[DC3 Malware Configuration Parser (DC3-MWCP)](https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP)

**Use dc3-mwcp tool to parse suspicious file:**
```
# python mwcp-tool.py -p <SUSPICIOUS FILE NAME>
```
---


**IDENTIFY MALWARE**

## PROCESS EXPLORER
```
Todo: Need more details here.
```


+ Step 1: Look at running processes by **running Process Explorer** (GUI) and identify potential indicators of compromise:

+ Step 2: Signature File Check:

+ Step 3: Strings Check:

+ Step 4: DLL View:

+ Step 5: Stop and Remove Malware:

+ Step 6: Clean up where malicious files Auto start on reboot.

+ Step 7: Process Monitor
[Process Monitor](https://technet.microsoft.com/en-us/sysinternals/processmonitor.aspx) 

+ Step 8: Repeat as needed to find all malicious files and process and/or combine with other tools and suites.