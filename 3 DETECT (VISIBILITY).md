# 3 DETECT (VISIBILITY)

**NETWORK MONITORING**

## TCPDUMP
---
**View ASCII (-A) or HEX (-X) traffic:**
```
# tcpdump -A
# tcpdump -X 
```

**View traffic with timestamps and don't convert addresses and be verbose:**
```
# tcpdump -tttt -n -vv
```

**Find top talkers after 1000 packets (Potential DDoS):**
```
# tcpdump -nn -c 1000 | awk '{print $3}' | cut -d. -f1-4 | sort -n | uniq -c | sort -nr
```

**Capture traffic on any interface from a target host and specific port and output to a file:**
```
# tcpdump -w <FILENAME>.pcap -i any dst <TARGET IP ADDRESS> and port 80 
```

**View traffic only between two hosts:**
```
# tcpdump host 10.0.0.1 && host 10.0.0.2 
```

**View all traffic except from a net or a host:**
```
# tcpdump not net 10.10 && not host 192.168.1.2 
```

**View host and either of two other hosts:**
```
# tcpdump host 10.10.10.10 && \(10.10.10.20 or 10.10.10.30\)
```

**Save pcap file on rotating size:**
```
# tcpdump -n -s65535 -c 1000 -w '%host_%Y-%m-%d_%H:%M:%S.pcap'
```

**Save pcap file to a remote host:**
```
# tcpdump -w - | ssh <REMOTE HOST ADDRESS> -p 50005 "cat - > /tmp/remotecapture.pcap"
```

**Grab traffic that contains the word pass:**
```
# tcpdump -n -A -s0 | grep pass
```

**Grab many clear text protocol passwords:**
```
# tcpdump -n -A -s0 port http or port ftp or port smtp or port imap or port pop3 | egrep -i 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:' --color=auto --line-buffered -B20
```

**Get throughput:**
```
# tcpdump -w - | pv -bert >/dev/null 
```

**Filter out ipv6 traffic:**
```
# tcpdump not ip6
```

**Filer out ipv4 traffic:**
```
# tcpdump ip6
```

**Script to move multiple tcpdump files to alternate location:**
```
#!/bin/bash
while true; do
sleep 1;
rsync -azvr -progress <USER NAME>@<IP ADDRESS>:<TRAFFIC DIRECTORY>/. <DESTINATION DIRECTORY/.
done 
```

**Look for suspicious and self-signed SSL certificates:**
```
Todo
```
---

**HONEY TECHNIQUES**

## WINDOWS
---
**Honey Ports Windows:**

[Getting A Better Pen Test](http://securityweekly.com/wp-content/uploads/2013/06/howtogetabetterpentest.pdf)

+ Step 1: Create new TCP Firewall Block rule on anything connecting on port 3333:
```
Todo

echo  @echo off *** >> <BATCH FILE NAME>.bat 
```

+ Step 2: Run Batch Script
```
<BATCH FILE NAME>.bat
```

**Windows Honey Ports PowerShell Script**

[Windows Honey Ports PowerShell Script](https://github.com/Pwdrkeg/honeyport/blob/master/honeyport.ps1)

+ Step 1: Download PowerShell Script
```
C:\> "%ProgramFiles%\Internet Explorer\iexplore.exe" https://github.com/Pwdrkeg/honeyport/blob/master/honeyport.ps1
```

+ Step 2: Run PowerShell Script 
```
C:\> honeyport.ps1
```

**Honey Hashes for Windows (Also for Detecting Mimikatz Use):**

[SEC522: Application Security](https://www.sans.org/cyber-security-courses/application-security-securing-web-apps-api-microservices/)

+ Step 1: Create Fake Honey Hash. Note enter a fake password and keep command prompts open to keep password in memory 
```
C:\> runas /user:yourdomain.com\fakeadministratoraccount /netonly cmd.exe
``` 

+ Step 2: Query for Remote Access Attempts 
```
C:\> wevtutil qe System /q:"*[System [(EventID=20274)]]" /f:text /rd:true /c:1 /r:remotecomputername
```

+ Step 3: Query for Failed Login Attempts
```
C:\> wevtutil qe Security /q:"*[System[(EventID=4624 or EventID=4625)]]" /f:text /rd:true /c:5 /r:remotecomputername 
```

+ Step 4: (Optional) Run queries in infinite loop with 30s pause
```
C:\> for /L %i in (1,0,2) do (Insert Step 2) & (Insert Step 3) & timeout 30
```
---

## LINUX
---
**Honey Ports Linux:**

+ Run a while loop to create TCP Firewall rules to block any hosts connecting on port 2222 
```
while [1]; echo "started"; do IP = `nc -v -l -p 2222 2>&1 1> /dev/null | grep from | cut -d[-f 3 | cut -d] -f 1`; iptables -A INPUT -p tcp -s ${IP} -j DROP ; done 
```

**Linux Honey Ports Python Script:**

[Linux Honey Ports Python Script](https://github.com/gchetrick/honeyports/blob/master/honeyports-0.5.py)

+ Step 1: Download Python Script
```
# wget https://github.com/gchetrick/honeyports/blob/master/honeyports-0.5.py 
```

+ Step 2: Run Python Script
```
# python honeyports-0.5.py -p <CHOOSE AN OPEN PORT> -h <HOST IP ADDRESS>
```

**Detect rogue scanning with Labrea Tarpit:**
```
# apt-get install labrea
# labrea -z -s -o -b -v -i eth0 2>&1 | tee -a log.txt 
```
---