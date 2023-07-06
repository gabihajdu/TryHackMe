IP address: 10.10.242.6


NMap scan:

PORT     STATE SERVICE       REASON  VERSION
80/tcp   open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2021-11-07T10:56:22+00:00
| ssl-cert: Subject: commonName=RetroWeb
| Issuer: commonName=RetroWeb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-11-06T10:48:03
| Not valid after:  2022-05-08T10:48:03
| MD5:   00dd df40 9bea 1cb4 20d0 5616 a699 d549
| SHA-1: a6c7 cbf8 04ef c00a d846 478b f339 7eea 19c2 47fd
| -----BEGIN CERTIFICATE-----
| MIIC1DCCAbygAwIBAgIQHBihPAVFxZ9OV+u4+6NBFzANBgkqhkiG9w0BAQsFADAT
| MREwDwYDVQQDEwhSZXRyb1dlYjAeFw0yMTExMDYxMDQ4MDNaFw0yMjA1MDgxMDQ4
| MDNaMBMxETAPBgNVBAMTCFJldHJvV2ViMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAttFbOnCmxs7qCfhahHn+PBpGy+r9jo8mTao92VS+nqClX2j62i5r
| fhWSHi1bJLJ9Ok7XmbXHOKUU9vaK5ZR94uRknZscrEpe8ianY/ZNEVX48tYXFmNV
| Xb/Ffu+UgSS5KTqflhBcRja6P5hBhJCUA6m1pm/Wwaif4MKBaYbCT7e+GEgyv/np
| oEeX0EHFfu2GivC7Olojw3IrpuUJ8qRNoV29CMynzOMTvFSXACmHlZN4iAMi5sm/
| QZMtCm4PliVZb3+ZTwsCl9W0zMPRoTN8cQcoZdcOENrkMSkxL01o7o6lqLhjs+So
| ehv8SUXXQYm15NrEaMdPn5vz/e9cZGREXQIDAQABoyQwIjATBgNVHSUEDDAKBggr
| BgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAGeafbbjJKz+
| Er4IhFMvYmyIKpJ/pQbzbblRXDveEdGpD4SxPj8fzpafBA0Kmqnb0ZacNBw/9egA
| 6aSiEXGL3kTxTcJ2NxrlWkoe1SNnU0BVrAjYRUL7IELhdQuJsevEGQ/ije7jqQd3
| DzKPjyrneAzBrkcIZR9s+JPhAL7v6AKduGSII807k4CoA+AbWpKBU5L6J0Z25Kr3
| vCBL9jSQna9U6wSkeVFPv99eXdC3+0inJ8LTBGEgkSIfN5cPyk3KQ/d7kgCGETjj
| PsTXFF46/FmiVvNsRjxfxACJjcB7xuBjNrPIF79jzeuC14rD7mEq1dQlMw/7MGH0
| zK/1RgU7UIw=
|_-----END CERTIFICATE-----
|_ssl-date: 2021-11-07T10:56:23+00:00; 0s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:56
Completed NSE at 05:56, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:56
Completed NSE at 05:56, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:56
Completed NSE at 05:56, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.83 sec

Gooooooooooooooooooobuster:

found: /retro

User:wade passwd:parzival

found exploit on machine: CVE-2019-1388

run the exploit: nt authority\system

root flag: THM{COIN_OPERATED_EXPLOITATION}

