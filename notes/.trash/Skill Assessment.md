# Easy
---
Nmap:
```
PORT     STATE SERVICE VERSION                                     
21/tcp   open  ftp     ProFTPD                                     
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)                                                   
| ssh-hostkey:                                                     
|   3072 3f4c8f10f1aebecd31247ca14eab846d (RSA)                    
|   256 7b30376750b9ad91c08ff702783b7c02 (ECDSA)                   
|_  256 889e0e07fecad05c60abcf1099cd6ca7 (ED25519)                 
53/tcp   open  domain  ISC BIND 9.16.1 (Ubuntu Linux)              
| dns-nsid:                                                        
|_  bind.version: 9.16.1-Ubuntu                                    
2121/tcp open  ftp     ProFTPD                                     
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kerne
```

### FTP
---
21: ftp.int.inlanefreight.htb
2121: Ceil's FTP anonymous:anonymous

### Users
----
Ceil:qwerty123

### SSH 
---
id_rsa in 21 anon

# Medium
----
Nmap:
```
PORT     STATE SERVICE       VERSION
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo:                                                         
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs                      
|   100003  2,3         2049/udp6  nfs   
|   100003  2,3,4       2049/tcp   nfs 
|   100003  2,3,4       2049/tcp6  nfs 
|   100005  1,2,3       2049/tcp   mountd               
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status     
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status                                                                                              
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC                                                                               
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn     
445/tcp  open  microsoft-ds?                                       
2049/tcp open  mountd        1-3 (RPC #100005)                     
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:                                                   
|   Target_Name: WINMEDIUM                                         
|   NetBIOS_Domain_Name: WINMEDIUM                                 
|   NetBIOS_Computer_Name: WINMEDIUM      
|   DNS_Domain_Name: WINMEDIUM                                     
|   DNS_Computer_Name: WINMEDIUM                                   
|   Product_Version: 10.0.17763                                    
|_  System_Time: 2022-12-26T11:00:02+00:00
|_ssl-date: 2022-12-26T11:00:09+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=WINMEDIUM
| Not valid before: 2022-12-25T10:56:25
|_Not valid after:  2023-06-26T10:56:25
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
                                                                   
Host script results:                                               
| smb2-time:                                                       
|   date: 2022-12-26T11:00:06                                      
|_  start_date: N/A                                                
| smb2-security-mode:                                              
|   311:                                                           
|_    Message signing enabled but not required

```

### NFS
----
```
111/tcp  open  rpcbind 2-4 (RPC #100000)
| nfs-showmount:                                                   
|_  /TechSupport                                                   
| nfs-statfs:                                                      
|   Filesystem    1K-blocks   Used        Available   Use%  Maxfilesize  Maxlink
|_  /TechSupport  41312252.0  16918640.0  24393612.0  41%   16.0T        1023
| nfs-ls: Volume /TechSupport                                      
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID         GID         SIZE   TIME                 FILENAME
| rwx------   4294967294  4294967294  65536  2021-11-11T00:09:49  . 
| ??????????  ?           ?           ?      ?                    ..
| rwx------   4294967294  4294967294  0      2021-11-10T15:19:28  ticket4238791283649.txt
| rwx------   4294967294  4294967294  0      2021-11-10T15:19:28  ticket4238791283650.txt
| rwx------   4294967294  4294967294  0      2021-11-10T15:19:28  ticket4238791283651.txt
| rwx------   4294967294  4294967294  0      2021-11-10T15:19:28  ticket4238791283652.txt
| rwx------   4294967294  4294967294  0      2021-11-10T15:19:28  ticket4238791283653.txt
| rwx------   4294967294  4294967294  0      2021-11-10T15:19:28  ticket4238791283654.txt
| rwx------   4294967294  4294967294  0      2021-11-10T15:19:29  ticket4238791283655.txt     
| rwx------   4294967294  4294967294  0      2021-11-10T15:19:29  ticket4238791283656.txt

```

### Users
----
alex:lol123!mD - works in rdp 
sa:87N1ns@slls83 - mssql db login
Administrator:87N1ns@slls83 - admin rdp acct

# Hard
---
Nmap:
```
TCP:
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack
110/tcp open  pop3    syn-ack
143/tcp open  imap    syn-ack
993/tcp open  imaps   syn-ack
995/tcp open  pop3s   syn-ack

UDP:
68/udp  open|filtered dhcpc
161/udp open          snmp

```

### SNMP
---
backup community string

### Users 
---
tom:NMds732Js2761

