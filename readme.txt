ip address: 10.10.18.122

Image of the clown: Pennywise

Nmap results:

PORT     STATE SERVICE            REASON  VERSION
80/tcp   open  http               syn-ack Microsoft IIS httpd 8.5
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS TRACE POST
|_  Potentially risky methods: TRACE
| http-robots.txt: 6 disallowed entries 
| /Account/*.* /search /search.aspx /error404.aspx 
|_/archive /archive.aspx
|_http-server-header: Microsoft-IIS/8.5
|_http-title: hackpark | hackpark amusements
3389/tcp open  ssl/ms-wbt-server? syn-ack
| ssl-cert: Subject: commonName=hackpark
| Issuer: commonName=hackpark
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2021-11-10T16:37:16
| Not valid after:  2022-05-12T16:37:16
| MD5:   2f3f 686b 8b59 a3c1 ae83 ddb2 702e 2580
| SHA-1: 9591 41b5 6838 8a8d 0a77 068d e64e 3e30 9e41 e6c3
| -----BEGIN CERTIFICATE-----
| MIIC1DCCAbygAwIBAgIQYChqhqwO85NDMSXXchDClTANBgkqhkiG9w0BAQUFADAT
| MREwDwYDVQQDEwhoYWNrcGFyazAeFw0yMTExMTAxNjM3MTZaFw0yMjA1MTIxNjM3
| MTZaMBMxETAPBgNVBAMTCGhhY2twYXJrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAorNfH65OXsPmRyIA2XSNavNB6m3539rGCf8qXE+2fKvOU51DOOeU
| jmq+p2wNHCSAkgSqrcDjhs9nS/v2SiQbOLBkI8qda+OH5mtM0Lo3OBOXzdxD7tdO
| /ATUP0tWNI3/9GWEU4jBo1oi7DAYMunTREmUsSPjWb4EuZY4IjgqLPD5WPJJSG1z
| 5bpG9MDBKp+10TZPEJIXL4rIL7zBGDQvs0bso0jg9VlAxG9XBSqFBrjwEJ8br+NF
| TE0JwiVLIE2szo8yOT7yIYKodaaGvPW4GadKOsK2k3AAtB8RzSWIsFle0W2WE4PN
| xXPOImayvHKyE2b9AZfFk0v9Z3O9gFSLhQIDAQABoyQwIjATBgNVHSUEDDAKBggr
| BgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQEFBQADggEBAFSXueclT7DI
| HeQX3CwEyYXQwa63TEREPjvGR3XbXlasTZ8KOUeZOGZvBUN0F2g+fVQcBQ7/VwSR
| tvXpG8UzmB6cXUiFpHsb+W6dI1ELisGk00n+K8Rg5WFuyqZZQzpjC4lfh5SuiJIK
| 1sqB1eFHYmuTY9P/POUI9gikV2EqJgi56pCADSIluoApodPfj9Px+DzkVRK48gz7
| cDgfBATwQhWfx+R35digSlyQSDKG+DOoqANsit77P86clf7ol2Dw0sRWl844CKO4
| 50a2jJrqi0qXhW8aDISI+2I+gOzCSsY0xzaJgN4rklHRRErbMLTW1TCf0gO2OhUj
| CVyT2aGcfjY=
|_-----END CERTIFICATE-----


BlogEngine.NET

hydra result: user admin pass 1qaz2wsx


__VIEWSTATE=GjbYqN0nqxModBvFV66ZZGG%2F4cwjbwsBTLPwGuS1yFnZOlPRRHyuxDaAwfHxkLTwGfzvCE8unvtw5AdUyPGM1KMXQPSs0XuzcEodRCqhUjEyGmil8ySEP0gKsETaBNIWfJHhlzP8VEtMcIH3ojEZL3jlhZAoggjm6R%2BZ2nI3XmHQEDte&__EVENTVALIDATION=X%2FYLzV%2F6K6YiaQ9K1itT3G8JCTwDVBlZqZLaI9Dd8RyM4e%2B9tGo31Ki1FSVRIVcd%2BBGnxRyqiG%2BlyP9i1mND5Q2FbPVXnpRNiOcHUAe57mgxznHWppFFUNWz7DOxaD1djm%2FGf1fu02cYhqd%2B0%2FTprJcdwcWe3uDsNcssUiHKR2vim2t2&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login Failed



Jeff user flag: 759bd8af507517bcfaede78a21a73e39

Admin user flag: 7e13d97f05f7ceb9881a3eb3d78d3e72