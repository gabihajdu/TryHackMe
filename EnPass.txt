ip: 10.10.50.160

rustscan:

PORT     STATE SERVICE     REASON
22/tcp   open  ssh         syn-ack
8001/tcp open  vcom-tunnel syn-ack


nmap:
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8a:bf:6b:1e:93:71:7c:99:04:59:d3:8d:81:04:af:46 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCicax/djwvuiP5H2ET5UJCYL3Kp7ukHPJ0YWsSBUc6o8O/wwzOkz82yJRrZAff40NmLEpbvf0Sxw2JhrtoxDmdj+FSHpV/xDUG/nRE0FU10wDB75fYP4VFKR8QbzwDu6fxkgkZ3SAWZ9R1MgjN3B49hywgwqMRNtw+z2r2rXeF56y1FFKotBtK1wA223dJ8BLE+lRkAZd4nOr5HFMwrO+kWgYzfYJgSQ+5LEH4E/X7vWGqjdBIHSoYOUvzGJJmCum2/MOQPoDw5B85Naw/aMQqsv7WM1mnTA34Z2eTO23HCKku5+Snf5amqVwHv8AfOFub0SS7AVfbIyP9fwv1psbP
|   256 40:fd:0c:fc:0b:a8:f5:2d:b1:2e:34:81:e5:c7:a5:91 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBENyLKEyFWN1XPyR2L1nyEK5QiqJAZTV2ntHTCZqMtXKkjsDM5H7KPJ5EcYg5Rp1zPzaDZxBmPP0pDF1Rhko7sw=
|   256 7b:39:97:f0:6c:8a:ba:38:5f:48:7b:cc:da:72:a8:44 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJmb0JdTeq8kjq+30Ztv/xe3wY49Jhc60LHfPd5yGiRx
8001/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: En-Pass
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


GOBUSTER on port 8001

gobuster dir  -u http://10.10.50.160:8001 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 64                                                                    1 ⨯
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.50.160:8001
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/01/18 08:08:50 Starting gobuster
===============================================================
/web (Status: 301)
/zip (Status: 301)
/server-status (Status: 403)
/reg.php
===============================================================
2023/01/18 08:13:39 Finished
===============================================================




gobuster dir  -u http://10.10.50.160:8001/web -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 64  
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.50.160:8001/web
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/01/18 08:14:51 Starting gobuster
===============================================================
/resources (Status: 301)
===============================================================
2023/01/18 08:19:46 Finished


gobuster dir  -u http://10.10.50.160:8001/web/resources -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 64  
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.50.160:8001/web/resources
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/01/18 08:20:25 Starting gobuster
===============================================================
/infoseek (Status: 301)
Progress: 13011 / 207644 (6.27%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2023/01/18 08:20:46 Finished
===============================================================


gobuster dir  -u http://10.10.50.160:8001/web/resources/infoseek -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 64  
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.50.160:8001/web/resources/infoseek
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/01/18 08:21:00 Starting gobuster
===============================================================
/configure (Status: 301)
Progress: 12806 / 207644 (6.17%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2023/01/18 08:21:18 Finished
===============================================================



 gobuster dir  -u http://10.10.50.160:8001/web/resources/infoseek/configure -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 64  
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.50.160:8001/web/resources/infoseek/configure
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/01/18 08:21:27 Starting gobuster
===============================================================
/key (Status: 200)
Progress: 13539 / 207644 (6.52%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2023/01/18 08:21:47 Finished
===============================================================
