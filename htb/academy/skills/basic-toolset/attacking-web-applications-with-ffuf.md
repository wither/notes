
Directory Fuzzing
```
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ
```

Extension Fuzzing
```shell
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ
```

Page Fuzzing
```shell
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
```

Recursive Fuzzing
```shell
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
```

Sub-domain Fuzzing
```shell
ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/
```

VHost Fuzzing
```shell
ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx
```

Parameter Fuzzing - GET
```shell
ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
```

Parameter Fuzzing - POST
```shell
ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
Parameter Fuzzing - POST
```

Value Fuzzing
```shell
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```
# Wordlists

Directory/Page Wordlist
```shell
/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
```

Extensions Wordlist
```shell
/opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt
```
Domain Wordlist
```shell
/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

Parameters Wordlist
```shell
/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt
```
# Misc

Add DNS entry
```shell
sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'
```

Create Sequence Wordlist
```shell
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

curl with POST
```shell
curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

