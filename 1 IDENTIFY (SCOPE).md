# 1 IDENTIFY (SCOPE)
**SCANNING AND VULNERABILITIES**

## NMAP
---
**Ping sweep for network:**
```
nmap -sn -PE <IP ADDRESS OR RANGE>
```

**Scan and show open ports:**
```
nmap --open <IP ADDRESS OR RANGE>
```

**Determine open services:**
```
nmap -sV <IP ADDRESS OR RANGE>
```

**Scan two common TCP ports, HTTP and HTTPS:**
```
nmap -p 80,443 <IP ADDRESS OR RANGE>
```

**Scan common UDP port, DNS:**
```
nmap -sU -p 53 <IP ADDRESS OR RANGE>
```

**Scan UDP and TCP together, be verbose on a single host and include optional skip ping:**
```
nmap -v -Pn -SU -ST -p U:53,111,137,T:21-25,80,139,8080 <IP ADDRESS> 
```
---

## NESSUS

## OPENVAS

**WINDOWS**

## NETWORK DISCOVERY
---
**Basic network discovery:**
```
C:\> net view /all

C:\> net view \\<HOST NAME>
```

**Basic ping scan and write output to file:**
```
C:\> for /L %I in (1,1,254) do ping -w 30 -n 1 192.168.1.%I | find "Reply" >> <OUTPUT FILENAME>.txt 
```
---

## DHCP
---
**Enable DHCP server logging:**
```
C:\> reg add HKLM\System\CurrentControlSet\Services\DhcpServer\Parameters /v ActivityLogFlag /t REG_DWORD /d 1 
```

**Default Location Windows 2003/2008/2012:**
```
C:\> %windir%\System32\Dhcp 
```
---