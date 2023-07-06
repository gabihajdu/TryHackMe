Ip address: 

Nmap:

ORT     STATE SERVICE       REASON  VERSION
80/tcp   open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: WIN-LU09299160F
|   NetBIOS_Domain_Name: WIN-LU09299160F
|   NetBIOS_Computer_Name: WIN-LU09299160F
|   DNS_Domain_Name: WIN-LU09299160F
|   DNS_Computer_Name: WIN-LU09299160F
|   Product_Version: 10.0.17763
|_  System_Time: 2022-02-02T15:58:41+00:00
| ssl-cert: Subject: commonName=WIN-LU09299160F
| Issuer: commonName=WIN-LU09299160F
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-02-01T15:57:54
| Not valid after:  2022-08-03T15:57:54
| MD5:   4012 05dd 17c3 1803 5e03 5264 48f8 8a3b
| SHA-1: 3937 31e4 8c7b bf10 1d49 12bd 545a e4b5 9825 71b2
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQFOXtN68c5pZHShYTOg/xDzANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9XSU4tTFUwOTI5OTE2MEYwHhcNMjIwMjAxMTU1NzU0WhcNMjIw
| ODAzMTU1NzU0WjAaMRgwFgYDVQQDEw9XSU4tTFUwOTI5OTE2MEYwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDE2sP5j6BbDKdSzkqRFhkqvUj5AvOgN26b
| hRs1dJXRYo0YUnzK2V2REOf1uUYxEl863e/r5QUjFdmMJ1APpBG+Zok7JBF4tBsV
| IWiOFMpvVmdxnIxWvLTy3hXbRcC1AOGS2SWYDFbeM89g7Zl5ycsj67LDsntHl2gv
| NW/jZehEJ90xutblA/nyzXCC+8MwB5/0fCtwROfduY3JjI7N6Qk9DmYaz65e8qlQ
| Bqi5B87LoWF4BPAUFN+y+ALLjJyZmngj1u2uhfSWJRn1W8pCrBCF+oFYTAoJAVEE
| AGL0GaIkggQBdZA210Y7v1Q3DS77rEm+seLA1nN8u5jQFquMMVulAgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAdq/9mL8PQRg7b/lGm8AZ56rKWMoQaF44Ai2e1Mm6DuWhB6kqHuCg640j
| ODvFW5Egcot6tSYTB6x9RI3vF20oDTdoCWTHtsMv6+gwJDXTM25yJ7crCpm6RsLq
| MSXq6BsGKM7dlS1PN92SqJ00zy1X9VA+pAs2wEgIFZFPHx5tfkEJbW/6rOxajLvS
| WG/6LuXQd2kjPEdrbtvWHfBoty4gOu8LFrPb6e4fXsj0LHSWkAa+OKSe2xUD7Z8r
| 3alsgZouIlRBSDtFRY0sKynxahNOQOigvKIHDYRrqSE1P51jA2Scr1y1dMr+Qo2V
| 2r464+VBNQyE5hH1yGHv5T4rsrw4GA==
|_-----END CERTIFICATE-----
|_ssl-date: 2022-02-02T15:59:47+00:00; +2s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s


Gobuster:

/search (Status: 200)
/blog (Status: 200)
/sitemap (Status: 200)
/rss (Status: 200)
/archive (Status: 301)
/categories (Status: 200)
/authors (Status: 200)
/Search (Status: 200)









Other info:

/robots.txt:

UmbracoIsTheBest!

# Use for all search robots
User-agent: *

# Define the directories not to crawl
Disallow: /bin/
Disallow: /config/
Disallow: /umbraco/
Disallow: /umbraco_client/


USER for umbraco: SG@anthem.com, password:UmbracoIsTheBest!

Umbraco version: 7.15.4

Log on to the machine using RDP : user: SG, password:UmbracoIsTheBest!

Find user.txt:THM{N00T_NO0T}

find admin password:

Enable show hidden files, then go to backups and change permission in order to be able to read the pass.

Admin pass: ChangeMeBaby1MoreTime

Root flag: C:\Users\Administrator\Desktop\root.txt

THM{Y0U_4R3_1337}
