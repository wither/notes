| HOST                        | PORT | PROTO | SERVICE      | VERSION                  |
| --------------------------- | ---- | ----- | ------------ | ------------------------ |
| 10.10.10.79 (valentine.htb) | 22   | tcp   | OpenSSH      | 5.9p1 Debian 5ubuntu1.10 |
| 10.10.10.79 (valentine.htb) | 443  | tcp   | Apache httpd | 2.2.22                   |
| 10.10.10.79 (valentine.htb) | 80   | tcp   | Apache httpd | 2.2.22                   |


## HEADERS
---
HTTP/1.1 200 OK
Date: Sun, 09 Jul 2023 19:14:17 GMT
Server: Apache/2.2.22 (Ubuntu)
X-Powered-By: PHP/5.3.10-1ubuntu3.26
Vary: Accept-Encoding
Content-Type: text/html

---

## DIRECTORIES
---
* /dev                  [--> http://valentine.htb/dev/]
* /index
* /server-status
* /decode

---

## USERS
---

---

## NOTES
---
* hype_key in /dev is in hex
* `:%s/ //g` in vim to remove whitespace 
* convert in cyberchef to reveal rsa key
* 
---
