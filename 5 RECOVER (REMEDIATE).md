# 5 RECOVER (REMEDIATE)

**PATCHING**

## WINDOWS
---
**Single Hotfix update for Windows 7 or higher:**
```
C:\> wusa.exe C:\<PATH TO HOTFIX>\Windows6.0-KB934307-x86.msu
```

**Set of single hotfix updates for pre Windows 7 by running a batch script:
```
@echo off
setlocal
set PATHTOFIXES=E:\hotfix
%PATHTOFIXES%\Q123456_w2k_sp4_x86.exe /Z /M
%PATHTOFIXES%\Ql23321_w2k_sp4_x86.exe /Z /M
%PATHTOFIXES%\Q123789_w2k_sp4_x86.exe /Z /M 
```

**To check and update Windows 7 or higher:**
```
C:\> wuauclt.exe /detectnow /updatenow
```
---

## LINUX
---
**Ubuntu:**
```
# apt-get update
# apt-get upgrade 
# apt-get dist-upgrade 
```

**Red Hat Enterprise Linux 2.1,3,4:**
```
# up2date
# up2date-nox --update
# up2date <PACKAGE NAME>
# up2date -u <PACKAGE NAME>
```

**Red Hat Enterprise Linux 5:**
```
# pup
```

**Red Hat Enterprise Linux 6:**
```
# yum update
# yum list installed <PACKAGE NAME>
# yum install <PACKAGE NAME>
# yum update <PACKAGE NAME> 
```
**Debian & Kali:** 
```
# apt-get update && apt-get upgrade
```
---

**BACKUP**

## WINDOWS
---
**Backup GPO Audit Policy to backup file:**
```
Todo
```
---

**KILL MALWARE PROCESS**

## WINDOWS
---
**Malware Removal:**

[GMER](http://www.gmer.net/)

```
C:\> gmer.exe (GUI) 
```

**Kill running malicious file:**
```
C:\> gmer.exe -killfile
C:\WINDOWS\system32\drivers\<MALICIOUS FILENAME>.exe
```

**Kill running malicious file in PowerShell:**
```
PS C:\> Stop-Process -Name <PROCESS NAME>
PS C:\> Stop-Process -ID <PID>
```
---

## LINUX
---
**Stop a malware process:**
```
# kill <MALICIOUS PID>
```

```
     The options are as follows:

     -s signal_name
             A symbolic signal name specifying the signal to be sent instead of the default TERM.

     -l [exit_status]
             If no operand is given, list the signal names; otherwise, write the signal name corresponding
             to exit_status.

     -signal_name
             A symbolic signal name specifying the signal to be sent instead of the default TERM.

     -signal_number
             A non-negative decimal integer, specifying the signal to be sent instead of the default TERM.

     The following PIDs have special meanings:

     -1      If superuser, broadcast the signal to all processes; otherwise broadcast to all processes
             belonging to the user.

     Some of the more commonly used signals:

     1       HUP (hang up)
     2       INT (interrupt)
     3       QUIT (quit)
     6       ABRT (abort)
     9       KILL (non-catchable, non-ignorable kill)
     14      ALRM (alarm clock)
     15      TERM (software termination signal)

     Some shells may provide a builtin kill command which is similar or identical to this utility.  Consult
     the builtin(1) manual page.

EXIT STATUS
     The kill utility exits 0 on success, and >0 if an error occurs.

EXAMPLES
     Terminate the processes with PIDs 142 and 157:

           kill 142 157

     Send the hangup signal (SIGHUP) to the process with PID 507:

           kill -s HUP 507
```

**Change the malware process from execution and move:**
```
# chmod -x /usr/sbin/<SUSPICIOUS FILE NAME>
# mkdir /home/quarantine/
# mv /usr/sbin/<SUSPICIOUS FILE NAME> /home/quarantine/
```
---