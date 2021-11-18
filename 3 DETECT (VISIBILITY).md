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