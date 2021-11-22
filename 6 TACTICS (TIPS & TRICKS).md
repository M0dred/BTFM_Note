# 6 TACTICS (TIPS & TRICKS)

**OS CHEATS**

## WINDOWS
---
**Pipe output to clipboard:**
```
C:\> some_command.exe | clip
```
---


**SNORT**

## SNORT RULES
---
**Snort Rules to detect Meterpreter traffic:**

[Metasploit Meterpreter Reverse HTTPS Snort Rule](https://blog.didierstevens.com/2015/06/16/metasploit-meterpreter-reverse-https-snort-rule/)

```
Todo, need add more
alert tcp $HOME_NET any-> $EXTERNAL_NET $HTTP_PORTS (msg:"Metasploit User Agent String"; 
flow:to_server,established; content:"User-Agent|3a|Mozilla/4,0 (compatible\; MSIE 6.0\; Windows NT 5.1) |0d 0a|"; http_header; classtype:trojan-activity;
reference:url,blog,didierstevens.com/2015/03/16/quickpost-metasploit-user-agent-strings/; sid:1618000;rev:1;)  
```
---

**DOS/DDOS**
## FINGERPRINT DOS/DDOS
---
**Fingerprinting the type of DoS/DDoS:**

[PCAP Files Are Great Arn't They??](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/pcap-files-are-great-arnt-they/)

**Volumetric:** Bandwidth consumption 
Example, sustaining sending 1Gb of traffic to 10Mb connection

[iftop](http://freshmeat.sourceforge.net/projects/iftop)

```
# iftop -n
```

**and Protocol:** Use of specific protocol Example, SYN Flood, ICMP Flood, UDP flood
```
# tshark -r <FILE NAME>,pcap -q -z io,phs
# tshark -c 1000 -q -z io,phs
# tcpdump -tnr $FILE | awk -F '.' '{print$1"."$2"."$3"."$4}' | sort | uniq -c | sort -n | tail
# tcpdump -qnn "tcp[tcpflags] & (tcp-syn) != 0"
# netstat -s
```

Example, isolate one protocol and or remove other protocols 
```
# tcpdump -nn not arp and not icmp and not udp
# tcpdump -nn tcp 
```
---

**TOOL SUITES**
## PREBUILT ISO, VIRTUAL MACHINE AND DISTRIBUTIONS
---
+ (KALI - Open Source Pentesting Distribution)[https://www.kali.org]
+ (SIFT - SANS Investigative Forensics Toolkit)[https://sift.readthedocs.io/en/latest/]
+ (REMNUX - A Linux Toolkit for Reverse-Engineering and Analyzing Malware)[https://remnux.org/]
+ (OPENVAS - Open Source vulnerability scanner and manager)[https://www.openvas.org/]
+ (Arkime ~formerly Moloch~ - Large scale IPv4 packet capturing (PCAP), indexing and database system)[https://github.com/arkime/arkime]
+ (SECURITY ONION - Linux distro for intrusion detection, network security monitoring, and log management)[https://securityonionsolutions.com/]
+ (NAGIOS - Network Monitoring, Alerting, Response, and Reporting Tool)[https://www.nagios.org/]
+ (OSSEC - Scalable, multi-platform, open source Hostbased Intrusion Detection System)[https://www.ossec.net/]
+ (SAMURAI WTF - Pre-configured web pen-testing environment)[https://www.inguardians.com/]
+ (RTIR - Request Tracker for Incident Response)[https://bestpractical.com/rtir/]
+ (HONEYDRIVE - Pre-configured honeypot software packages)[https://sourceforge.net/projects/honeydrive/]
+ (The Enhanced Mitigation Experience Toolkit - helps prevent vulnerabilities in software from being successfully exploited)[https://support.microsoft.com/en-us/topic/emet-mitigations-guidelines-b529d543-2a81-7b5a-d529-84b30e1ecee0]
+ (ATTACK SURFACE ANALYZER BY MICROSOFT - Baseline Tool)[https://techcommunity.microsoft.com/t5/security-compliance-and-identity/announcing-attack-surface-analyzer-2-0/ba-p/487961]
+ (WINDOWS TO GO - USB Portable Windows 8)[https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-8.1-and-8/hh831833(v=ws.11)?redirectedfrom=MSDN]
+ (WINFE - Windows Forensic Environment on CD/USB)[https://winfe.wordpress.com/]
+ (DCEPT - Deploying and detecting use of Active)
+ (Directory honeytokens)[https://www.secureworks.com/blog/dcept]
+ (TAILS - The Amnesic Incognito Live System)[https://tails.boum.org/]

---