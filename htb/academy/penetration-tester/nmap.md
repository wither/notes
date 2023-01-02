
## Host Discovery
---
Scan network range:
```bash
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```

## Port Scanning
---
Basic TCP scan:
```shell
sudo nmap 10.129.2.28 -F
```

Basic UDP scan:
```shell
sudo nmap 10.129.2.28 -F -sU
```

Trace the packets:
```shell
sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping
```

## Output
---
All outputs:
```shell
sudo nmap 10.129.2.28 -F -oA location
```

Normal output (.nmap):
```shell
sudo nmap 10.129.2.28 -F -oN location
```

Greppable output (.gnmap)
```shell
sudo nmap 10.129.2.28 -F -oG location
```

XML output (.xml):
```shell
sudo nmap 10.129.2.28 -F -oX location
```

## Services
---
Scan service versions:
```shell
sudo nmap 10.129.2.28 -F -sV
```

## Scripts
---
Default scripts:
```shell
sudo nmap <target> -sC
```

Specific scripts category:
```shell
sudo nmap <target> --script <category>
```

Defined scripts:
```shell
sudo nmap <target> --script <script-name>,<script-name>
```

## Performance
---
Optimised RTT:
```shell
sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
```

Reduced retries:
```shell
sudo nmap 10.129.2.0/24 -F --max-retries 0
```

Optimised rates:
```shell
sudo nmap 10.129.2.0/24 -F -oN tnet.minrate300 --min-rate 300
```

Timing:
```shell
sudo nmap 10.129.2.0/24 -F -oN tnet.T5 -T (1-5)
```

## Firewall and IDS/IPS Evasion 
---
SYN-scan:
```shell
sudo nmap 10.129.2.28 -p 21,22,25 -sS -Pn -n --disable-arp-ping --packet-trace
```

ACK-scan:
```shell
sudo nmap 10.129.2.28 -p 21,22,25 -sA -Pn -n --disable-arp-ping --packet-trace
```

Using decoys:
```shell
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
```

Test specific firewall rule:
```shell
sudo nmap 10.129.2.28 -n -Pn -p445 -O
```

Scan using different source IP:
```shell
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
```

Scan using DNS port:
```shell
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
```