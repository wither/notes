# Aero

| Name      | IP           | Difficulty | OS    |
| --------- | ------------ | ---------- | ----- |
| aero | 10.10.11.237 | Easy       | Linux |

## NMAP

| HOST                    | PORT | PROTO | SERVICE             | VERSION |
| ----------------------- | ---- | ----- | ------------------- | ------- |
| 10.10.11.237 (aero.htb) | 80   | tcp   | Microsoft IIS httpd | 10.0    |

## HEADERS

```
HTTP/1.1 200 OK
Cache-Control: no-cache, no-store
Pragma: no-cache
Content-Length: 0
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/10.0
Set-Cookie: .AspNetCore.Antiforgery.SV5HtsIgkxc=CfDJ8KhwwGdRThZIsdKv2UEKBTSZCjJGccG15sVcZsBS5QgInNh_gjrsps8qZITcCB4QhkEcd0uhI7L2cjELPobfbbMzCWathss79MktfFylZLSntmt_sB5HAAUjZ4b0Kq4Qt5BySSUfbGWH_fQthtwNvFU; path=/; samesite=strict; httponly
X-Frame-Options: SAMEORIGIN
X-Powered-By: ARR/3.0
Date: Sat, 04 Nov 2023 10:40:46 GMT
```

## DIRECTORIES



## USERS



## NOTES

- accept=".theme, .themepack"
- CVE-2023-38146
- Turn this windows C reverse shell into the malicious VerifyThemeVersion dll https://raw.githubusercontent.com/izenynn/c-reverse-shell/main/windows.c
- See ippsec video on Aero 6:32
- Compile the dll `x86_64-w64-mingw32-gcc-win32 main.c -shared -lws2_32 -o VerifyThemeVersion.dll`
