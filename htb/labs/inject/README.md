# Inject

| Name      | IP           | Difficulty | OS    |
| ------ | ------------ | ---------- | ----- |
| inject | 10.10.11.204 | Easy       | Linux |

## NMAP

| HOST         | PORT | PROTO | SERVICE     | VERSION                 |
| ------------ | ---- | ----- | ----------- | ----------------------- |
| 10.10.11.204 | 22   | tcp   | OpenSSH     | 8.2p1 Ubuntu 4ubuntu0.5 |
| 10.10.11.204 | 8080 | tcp   | Nagios NSCA |                         |


## HEADERS



## DIRECTORIES

- /register
- /error
- /upload
- /blogs
- /environment



## USERS

- phil



## NOTES

- LFI `http://inject.htb:8080/show_image?img=/../../../../../../../../etc/passwd`
