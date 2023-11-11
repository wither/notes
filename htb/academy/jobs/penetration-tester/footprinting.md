
# Domain Information
---
Certificate transparency:
```shell
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .
```

Filter certificate by unique subdomains:
```shell
export TARGET="facebook.com"

curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u > "$TARGET".sh.txt

head -n20 facebook.com.sh.txt

```

Filter certificate by unique subdomains (OpenSSL):
```shell
export TARGET="facebook.com"
export PORT="443"
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "${TARGET}:${PORT}" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u
```

Filter for company hosted servers:
```shell
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
```

Shodan IP list:
```shell
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done
for i in $(cat ip-addresses.txt);do shodan host $i;done
```

DNS Records:
```shell
dig any inlanefreight.com
```

# Cloud Resources 
---

AWS Google dork:
```shell
intext:<target> inurl:amazonaws.com
```

Azure Google dork:
```shell
intext:<target> inurl:blob.core.windows.net
```

Useful website:
```
buckets.grayhatwarfare.com
```

# FTP
---

Download all available files:
```shell
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```

Interact with the service to gather information:
```shell
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```

Nmap script scan:
```shell
sudo nmap -sV -p21 -sC -A 10.129.14.136
```

# SMB 
---

Connect to the share:
```shell
smbclient -N -L //10.129.14.128
```

Nmap script scan:
```shell
sudo nmap 10.129.14.128 -sV -sC -p139,445
```

RPCclient:
```shell
rpcclient -U "" 10.129.14.128
```

SMBmap:
```shell
smbmap -H 10.129.14.128
```

CrackMapExec
```shell
crackmapexec smb 10.129.14.128 --shares -u '' -p ''
```

# NFS
---

Nmap script scan:
```shell
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
```

Show available shares:
```shell
showmount -e 10.129.14.128
```

Mounting a share:
```shell
mkdir target-NFS
mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NFS
tree .
```

Unmounting from a share:
```shell
cd ..
wther@htb[/htb]$ umount ./target-NFS
```

# DNS 
---

NS query:
```shell
dig ns inlanefreight.htb @10.129.14.128
```

ANY query:
```shell
dig any inlanefreight.htb @10.129.14.128
```

AXFR zone transfer with dig:
```shell
dig axfr inlanefreight.htb @10.129.14.128
```

Subdomain brute-forcing:
```shell
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

# SMTP
---

Connect with telnet:
```shell
telnet 10.129.14.128 25
```

Nmap script scan:
```shell
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
```

SMTP user brute-force:
```shell
python3 smtp-user-enum.py 10.129.200.129 /home/wither/htb/academy/smtp_names.txt
```

# IMAP/POP3
---

Nmap script scan:
```shell
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```

cURL mailboxes (authenticated):
```shell
curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd
```

TLS encrypted interaction:
```shell
openssl s_client -connect 10.129.14.128:pop3s/imaps
```

Login:
```
A1 LOGIN username password
```

List folders/mailboxes:
```
A1 LIST "" *
```

Select mailbox:
```
A1 SELECT INBOX
```

Fetch messages:
```
A1 FETCH 1:*
```

Fetch message content:
```
A1 FETCH 2 body[]
```

# SNMP
---

SNMPwalk:
```shell
snmpwalk -v2c -c public 10.129.14.128
```

Brute-force community strings:
```shell
onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt 10.129.14.128
```

Use braa to enumerate OIDs:

```shell
braa <community string>@<IP>:.1.3.6.*
```

# MySQL
---

Nmap script scan:
```shell
sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
```

Login to MySQL server:
```shell
mysql -u root -pP4SSw0rd -h 10.129.14.128
```

# MSSQL
---

Nmap MSSQL script scan:
```shell
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```

MSSQL ping in metasploit:
```shell
auxiliary(scanner/mssql/mssql_ping) > set rhosts 10.129.201.248
```

Connecting with Mssqlclient.py:
```shell
mssqlclient.py Administrator@10.129.201.248 -windows-auth
```

# IPMI
---

Nmap script scan:
```shell
sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```

Metasploit version scan3£
```shell
use auxiliary/scanner/ipmi/ipmi_version 
```

Metasploit dump IPMI hashes:
```shell
use auxiliary/scanner/ipmi/ipmi_dumphashes
```

Crack IPMI hash with john:
```shell
john --fork=8 --incremental:alpha --format=rakp hash
```

### Default Credentials:

**HP Integrated Lights Out (iLO)**
`Administrator:<factory randomized 8-character string>`

**Dell Remote Access Card (iDRAC, DRAC)**
`root:calvin`

**IBM Integrated Management Module (IMM)**
`USERID:PASSW0RD (with a zero)`

**Fujitsu Integrated Remote Management Controller**
`admin:admin`

**Supermicro IPMI (2.0)**
`ADMIN:ADMIN`

**Oracle/Sun Integrated Lights Out Manager (ILOM)**
`root:changeme`

ASUS iKVM BMC
`admin:admin`

# SSH
---
ssh-audit:
```shell
./ssh-audit.py 10.129.14.132
```

change authentication method:
```shell
ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password
```

# Rsync
---

Scan for rsync:
```shell
sudo nmap -sV -p 873 127.0.0.1
```

Probe for accessible shares:
```shell
nc -nv 127.0.0.1 873
```

Enumerate open share:
```shell
rsync -av --list-only rsync://127.0.0.1/dev
```

# R-Services
---

Nmap scan for r-services:
```shell
nmap -sV -p 512,513,514 10.0.17.2
```

Login using r-login:
```shell
rlogin 10.0.17.2 -l htb-student
```

List authenticated users using rusers:
```shell
rusers -al 10.0.17.5
```

# RDP
---

Nmap script scan:
```shell
nmap -sV -sC 10.129.201.248 -p3389 --script rdp*
```

RDP security check:
```shell
./rdp-sec-check.pl 10.129.201.248
```

Initiate rdp session:
```shell
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248
```

# WinRM
---
Nmap script scan:
```shell
nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n
```

Interaction with evil-winrm:
```shell
evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!
```

# WMI
---
Footprinting:
```shell
wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"
```
