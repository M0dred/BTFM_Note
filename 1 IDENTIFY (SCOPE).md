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

## DNS
---
**Default location Windows 2003:**
```
C:\> %SystemRoot%\System32\Dns 
```

**Default location Windows 2008:**
```
C:\> %SystemRoot%\System32\Winevt\Logs\MicrosoftWindows-DNSServer%4Analytical.etl
```

[LogLevel](https://technet.microsoft.com/enus/library/cc940779.aspx)


**Enable DNS Logging:**
```
C:\> DNSCmd <DNS SERVER NAME> /config /logLevel 0x8100F331
```

**Set log location:**
```
C:\> DNSCmd <DNS SERVER NAME> /config /LogFilePath <PATH TO LOG FILE>
```

**Set size of log file:**
```
C:\> DNSCmd <DNS SERVER NAME> /config /logfilemaxsize 0xffffffff
```

---

## HASHING
---
**File Checksum Integrity Verifier (FCIV):**

[File Checksum Integrity Verifier](https://support.microsoft.com/en-us/topic/d92a713f-d793-7bd8-b0a4-4db811e29559)

**Hash a file:**
```
C:\> fciv.exe <FILE TO HASH>
```

**Hash all files on C:\ into a database file:**
```
C:\> fciv.exe c:\ -r -mdS -xml <FILE NAME>.xml 
```

**List all hashed files:**
```
C:\> fciv.exe -list -shal -xml <FILE NAME>.xml
```

**Verify previous hashes in db with file system:**
```
C:\> fciv.exe -v -shal -xml <FILE NAME>.xml
```

**Note: May be possible to create a master db and compare to all systems from a cmd line. 
Fast baseline and difference.**

[Get-FileHash](https://technet.microsoft.com/enus/library/dn520872.aspx)

```
C:\> certutil -hashfile <FILE TO HASH> SHAl
C:\> certutil -hashfile <FILE TO HASH> MD5
PS C:\> Get-FileHash <FILE TO HASH> I Format-List
PS C:\> Get-FileHash -algorithm md5 <FILE TO HASH>
```

---

## NETBIOS
---
**Basic nbtstat scan:**
```
C:\> nbtstat -A <IP ADDRESS>
```

**Cached NetBIOS info on localhost:**
```
C:\> nbtstat -c
```

**Script loop scan:**
```
C:\> for /L %I in (1,1,254) do nbstat -An 192.168.l.%I 
```

---