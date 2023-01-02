
# WHOIS
---
WHOIS:
```shell
export TARGET="facebook.com"
whois $TARGET
```

# DNS
---
Query A records:
```shell
dig a www.facebook.com @1.1.1.1
```

Query PTR records for an IP:
```shell
dig -x 31.13.92.36 @1.1.1.1
```

Query ANY records:
```shell
dig any google.com @8.8.8.8
```

Query TXT records:
```shell
dig txt facebook.com @1.1.1.1
```

Query MX records:
```shell
dig mx facebook.com @1.1.1.1
```

# Passive Subdomain Enumeration
---
Virustotal's 'Relation' tab.

Useful certificate websites:
-   [https://censys.io](https://censys.io)
-   [https://crt.sh](https://crt.sh)

theHarvester sources:
```shell-session
baidu
bufferoverun
crtsh
hackertarget
otx
projecdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
```

Passive subdomain enumeration using theHarvester:
```shell
export TARGET="facebook.com"
cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done
```

Extract and sort results:
```shell
cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"
```

Merge files:
```shell
cat facebook.com_*.txt | sort -u > facebook.com_subdomains_passive.txt
```

# Passive Infrastructure Identification
---
Crawl waybackmachine urls;
```shell-session
waybackurls -dates https://facebook.com > waybackurls.txt
```

# Active Infrastructure Identification 
---
cURL HTTP-Headers:
```shell-session
curl -I http://${TARGET}
```

Analyse website technologies using whatweb:
```shell-session
whatweb -a3 https://www.facebook.com -v
```

Detect website security using wafw00f:
```shell-session
wafw00f -v https://www.tesla.com
```

# Active Subdomain Enumeration 
---
Manual zone transfer test:
```shell-session
2zonetransfer.me
```
```shell-session
nslookup -type=any -query=AXFR zonetransfer.me nsztm1.digi.ninja
```

Brute-forcing using gobuster:
```shell
export TARGET="facebook.com"
export NS="d.ns.facebook.com"
xport WORDLIST="numbers.txt"
gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"
```

# vHosts
---
Fuzz vhosts with ffuf:
```shell
ffuf -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612
```

# Crawling
---
Recursive directory crawling with ffuf:
```shell
ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
```

Dynamic wordlist generation using cewl:
```shell
cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10
```

