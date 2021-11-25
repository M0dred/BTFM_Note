# 2 PROTECT (DEFEND)

**WINDOWS**

## DISABLE/STOP SERVICES
---
**Get a list of services and disable or stop:** 
```
C:\> sc query
C:\> sc config "<SERVICE NAME>" start= disabled
C:\> sc stop "<SERVICE NAME>"
C:\> wmic service where name='<SERVICE NAME>' call ChangeStartmode Disabled 
```
---

## HOST SYSTEM FIREWALLS
---
**Show all rules:**
```
C:\> netsh advfirewall firewall show rule name=all
```

**Set firewall on/off:**
```
C:\> netsh advfirewall set currentprofile state on
C:\> netsh advfirewall set currentprofile firewallpolicy blockinboundalways,allowoutbound
C:\> netsh advfirewall set publicprofile state on
C:\> netsh advfirewall set privateprofile state on
C:\> netsh advfirewall set domainprofile state on
C:\> netsh advfirewall set allprofile state on
C:\> netsh advfirewall set allprof ile state off
```

**Set firewall rules examples:**
```
C:\> netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80
C:\> netsh advfirewall firewall add rule name="My Application" dir=in action=allow program="C:\MyApp\MyApp.exe" enable=yes

C:\> netsh advfirewall firewall add rule name="My Application" dir=in action=allow program="C:\MyApp\MyApp.exe" enable=yes remoteip=157.60.0.1,172.16.0.0/16,LocalSubnet profile=domain

C:\> netsh advfirewall firewall add rule name="My Application" dir=in action=allow program="C:\MyApp\MyApp.exe" enable=yes
remoteip=157.60.0.1,172.16.0.0/16,LocalSubnet profile=domain

C:\> netsh advfirewall firewall add rule name="My Application" dir=in action=allow program="C:\MyApp\MyApp.exe" enable=yes
remoteip=157.60.0.1,172.16.0.0/16,LocalSubnet profile=private

C:\> netsh advfirewall firewall delete rule name=rule name program="C:\MyApp\MyApp.exe"
C:\> netsh advfirewall firewall delete rule name=rule name protocol=udp localport=500
C:\> netsh advfirewall firewall set rule group="remote desktop" new enable=Yes prof ile=domain
C:\> netsh advfirewall firewall set rule group="remote desktop" new enable=No profile=public 
```

**Setup togging location:**
```
C:\> netsh advfirewall set currentprofile logging
C:\<LOCATION>\<FILE NAME> 
```

**Windows firewall tog location and settings:**
```
C:\>more %systemroot%\system32\LogFiles\Firewall\pfirewall.log
C:\> netsh advfirewall set allprofile logging maxfilesize 4096
C:\> netsh advfirewall set allprofile logging droppedconnections enable
C:\> netsh advfirewall set allprofile logging allowedconnections enable   
```

**Display firewall logs:**
```
PS C:\> Get-Content $env:systemroot\system32\LogFiles\Firewall\pfirewall.log
```
---

## PASSWORDS 
---
**Change password:**
```
C:\> net user <USER NAME> * /domain
C:\> net user <USER NAME> <NEW PASSWORD>
```
**Change password remotely:**

[Change password remotely](https://docs.microsoft.com/en-au/sysinternals/downloads/pspasswd)

```
C:\> pspasswd.exe \\<IP ADDRESS or NAME OF REMOTECOMPUTER> -u <REMOTE USER NAME> -p <NEW PASSWORD>
PS C:\> pspasswd.exe \\<IP ADDRESS or NAME OF REMOTECOMPUTER> 
```
---

## HOST FILE
---
**Flush DNS of malicious domain/IP:**
```
C:\> ipconfig /flushdns
```

**Flush NetBios cache of host/IP:**
```
C:\> nbtstat -R 
```

**Add new malicious domain to hosts file, and route to localhost:**
```
C:\> echo 127.0.0.1 <MALICIOUS DOMAIN> >> C:\Windows\System32\drivers\etc\hosts
```

**Check if hosts file is working, by sending ping to 127.0.0.1:**
```
C:\> ping <MALICIOUS DOMAIN> -n 1
```
---

## WHITELIST
---
**Use a Proxy Auto Config(PAC) file to create Bad URL or IP List (IE, Firefox, Chrome):**
```
Todo
```
---

## APPLICATION RESTRICTIONS
---
**Applocker - Server 2008 R2 or Windows 7 or higher: Using GUI Wizard configure:**
+ Executable Rules (. exe, . com)
+ DLL Rules ( .dll, .ocx)
+ Script Rules (.psl, .bat, .cmd, .vbs, .js)
+ Windows Install Rules ( .msi, .msp, .mst)

**Steps to employ Applocker (GUI is needed for digital signed app restrictions):**
```
Todo
```
---

# LINUX

## DISABLE/STOP SERVICES
---
**Services information:**
```
# service --status-all
# ps -ef
# ps -aux
```
---


## HOST SYSTEM FIREWALLS
---
**Export existing iptables firewall rules:**
```
# iptables-save > firewall.out
```

**Apply iptables:**
```
# iptables-restore < firewall.out
```

**Example iptables commands (IP, IP Range, Port Blocks):**
```
# iptables -A INPUT -s 10.10.10.10 -j DROP
# iptables -A INPUT -s 10,10.10.0/24 -j DROP
# iptables -A INPUT -p tcp --dport 10.10.10.10 -j DROP
# iptables -A INPUT -p tcp --dport ssh -j DROP

```

**Block all connections:**
```
# iptables-policy INPUT DROP
# iptables-policy OUTPUT DROP
# iptables-policy FORWARD DROP

```

**Log all denied iptables rules:**
```
# iptables -I INPUT 5 -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7
```

**Save all current iptables rules:**
**Ubuntu / RedHat / CentOS:**
```
# /etc/init.d/iptables save
# /sbin/service iptables save
# /sbin/iptables-save
```

**List all current iptables rules:**
```
# iptables -L
```

**Flush all current iptables rules:**
```
# iptables -F
```

**Start/Stop ufw service:**
```
Todo
```
---