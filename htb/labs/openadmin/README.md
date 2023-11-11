| HOST         | PORT | PROTO | SERVICE      | VERSION                 |
| ------------ | ---- | ----- | ------------ | ----------------------- |
| 10.10.10.171 | 22   | tcp   | OpenSSH      | 7.6p1 Ubuntu 4ubuntu0.3 |
| 10.10.10.171 | 80   | tcp   | Apache httpd | 2.4.29                  |


## HEADERS
---
HTTP/1.1 200 OK
Date: Sat, 08 Jul 2023 16:46:16 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Thu, 21 Nov 2019 14:08:45 GMT
ETag: "2aa6-597dbd5dcea8b"
Accept-Ranges: bytes
Content-Length: 10918
Vary: Accept-Encoding
Content-Type: text/html

---

## DIRECTORIES
---
/music
/artwork
/ona

---

## USERS
---
jimmy n1nj4W4rri0R! 
joanna bloodninjas (ssh passphrase)
ona_sys n1nj4W4rri0R! (mysql)


---

## NOTES
---
* OpenNetAdmin - v18.1.1
* https://github.com/amriunix/ona-rce
* database credentials in `/var/www/html/ona/local/config$ database_settings.inc.php`
* use password to ssh as jimmy
* service running on port `52846`
* `sudo ssh -L 52846:127.0.0.1:52846 jimmy@openadmin.htb`
* upload php shell to `/var/www/interal` and access the file with a listener open
* save `/home/joanna/.ssh/id_rsa` and `chmod 600 id_rsa`
* `ssh2john id_rsa > ssh.john`
* `john -wordlist=/usr/share/wordlists/rockyou.txt ssh.john --format=SSH`
* login and `sudo -l` shows sudo nano permissions
* nano gtfobin


---
