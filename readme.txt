ip address:10.10.124.51

Nmap:

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:85:ec:54:f2:01:b1:94:40:de:42:e8:21:97:20:80 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDaKxKph/4I3YG+2GjzPjOevcQldxrIll8wZ8SZyy2fMg3S5tl5G6PBFbF9GvlLt1X/gadOlBc99EG3hGxvAyoujfdSuXfxVznPcVuy0acAahC0ohdGp3fZaPGJMl7lW0wkPTHO19DtSsVPniBFdrWEq9vfSODxqdot8ij2PnEWfnCsj2Vf8hI8TRUBcPcQK12IsAbvBOcXOEZoxof/IQU/rSeiuYCvtQaJh+gmL7xTfDmX1Uh2+oK6yfCn87RpN2kDp3YpEHVRJ4NFNPe8lgQzekGCq0GUZxjUfFg1JNSWe1DdvnaWnz8J8dTbVZiyNG3NAVAwP1+iFARVOkiH1hi1
|   256 77:c7:c1:ae:31:41:21:e4:93:0e:9a:dd:0b:29:e1:ff (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE52sV7veXSHXpLFmu5lrkk8HhYX2kgEtphT3g7qc1tfqX4O6gk5IlBUH25VUUHOhB5BaujcoBeId/pMh4JLpCs=
|   256 07:05:43:46:9d:b2:3e:f0:4d:69:67:e4:91:d3:d3:7f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINZwq5mZftBwFP7wDFt5kinK8mM+Gk2MaPebZ4I0ukZ+
80/tcp   open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
8000/tcp open  http    syn-ack (PHP 7.2.32-1)
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     Date: Mon, 29 Nov 2021 15:10:53 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.32-1+ubuntu18.04.1+deb.sury.org+1
|     Cache-Control: private, must-revalidate
|     Date: Mon, 29 Nov 2021 15:10:53 GMT
|     Content-Type: text/html; charset=UTF-8
|     pragma: no-cache
|     expires: -1
|     X-Debug-Token: 190e61
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Bolt | A hero is unleashed</title>
|     <link href="https://fonts.googleapis.com/css?family=Bitter|Roboto:400,400i,700" rel="stylesheet">
|     <link rel="stylesheet" href="/theme/base-2018/css/bulma.css?8ca0842ebb">
|     <link rel="stylesheet" href="/theme/base-2018/css/theme.css?6cb66bfe9f">
|     <meta name="generator" content="Bolt">
|     </head>
|     <body>
|     href="#main-content" class="vis
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Date: Mon, 29 Nov 2021 15:10:53 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.32-1+ubuntu18.04.1+deb.sury.org+1
|     Cache-Control: public, s-maxage=600
|     Date: Mon, 29 Nov 2021 15:10:53 GMT
|     Content-Type: text/html; charset=UTF-8
|     X-Debug-Token: d9bffc
|     <!doctype html>
|     <html lang="en-GB">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Bolt | A hero is unleashed</title>
|     <link href="https://fonts.googleapis.com/css?family=Bitter|Roboto:400,400i,700" rel="stylesheet">
|     <link rel="stylesheet" href="/theme/base-2018/css/bulma.css?8ca0842ebb">
|     <link rel="stylesheet" href="/theme/base-2018/css/theme.css?6cb66bfe9f">
|     <meta name="generator" content="Bolt">
|     <link rel="canonical" href="http://0.0.0.0:8000/">
|     </head>
|_    <body class="front">
|_http-generator: Bolt
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Bolt | A hero is unleashed
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.91%I=7%D=11/29%Time=61A4ED7D%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,14F1,"HTTP/1\.0\x20200\x20OK\r\nDate:\x20Mon,\x2029\x20Nov\x2
SF:02021\x2015:10:53\x20GMT\r\nConnection:\x20close\r\nX-Powered-By:\x20PH
SF:P/7\.2\.32-1\+ubuntu18\.04\.1\+deb\.sury\.org\+1\r\nCache-Control:\x20p
SF:ublic,\x20s-maxage=600\r\nDate:\x20Mon,\x2029\x20Nov\x202021\x2015:10:5
SF:3\x20GMT\r\nContent-Type:\x20text/html;\x20charset=UTF-8\r\nX-Debug-Tok
SF:en:\x20d9bffc\r\n\r\n<!doctype\x20html>\n<html\x20lang=\"en-GB\">\n\x20
SF:\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20charset=\"
SF:utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20name=\"viewport\"\x2
SF:0content=\"width=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<title>Bolt\x20\|\x20
SF:A\x20hero\x20is\x20unleashed</title>\n\x20\x20\x20\x20\x20\x20\x20\x20<
SF:link\x20href=\"https://fonts\.googleapis\.com/css\?family=Bitter\|Robot
SF:o:400,400i,700\"\x20rel=\"stylesheet\">\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20<link\x20rel=\"stylesheet\"\x20href=\"/theme/base-2018/css/bulma\.css
SF:\?8ca0842ebb\">\n\x20\x20\x20\x20\x20\x20\x20\x20<link\x20rel=\"stylesh
SF:eet\"\x20href=\"/theme/base-2018/css/theme\.css\?6cb66bfe9f\">\n\x20\x2
SF:0\x20\x20\t<meta\x20name=\"generator\"\x20content=\"Bolt\">\n\x20\x20\x
SF:20\x20\t<link\x20rel=\"canonical\"\x20href=\"http://0\.0\.0\.0:8000/\">
SF:\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body\x20class=\"front\">\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20<a\x20")%r(FourOhFourRequest,16C3,"HTTP/
SF:1\.0\x20404\x20Not\x20Found\r\nDate:\x20Mon,\x2029\x20Nov\x202021\x2015
SF::10:53\x20GMT\r\nConnection:\x20close\r\nX-Powered-By:\x20PHP/7\.2\.32-
SF:1\+ubuntu18\.04\.1\+deb\.sury\.org\+1\r\nCache-Control:\x20private,\x20
SF:must-revalidate\r\nDate:\x20Mon,\x2029\x20Nov\x202021\x2015:10:53\x20GM
SF:T\r\nContent-Type:\x20text/html;\x20charset=UTF-8\r\npragma:\x20no-cach
SF:e\r\nexpires:\x20-1\r\nX-Debug-Token:\x20190e61\r\n\r\n<!doctype\x20htm
SF:l>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initia
SF:l-scale=1\.0\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20<title>Bolt\x20\|\x20A\x20hero\x20is\x20unleashed</title>\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20<link\x20href=\"https://fonts\.googleapis
SF:\.com/css\?family=Bitter\|Roboto:400,400i,700\"\x20rel=\"stylesheet\">\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"
SF:/theme/base-2018/css/bulma\.css\?8ca0842ebb\">\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/theme/base-2018/css/the
SF:me\.css\?6cb66bfe9f\">\n\x20\x20\x20\x20\t<meta\x20name=\"generator\"\x
SF:20content=\"Bolt\">\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20<a\x20href=\"#main-content\"\x20class=\"
SF:vis");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


Nikto:

Gobuster:

/search (Status: 200)
/pages (Status: 200)

results on port 8000/bolt:

/about (Status: 302)
/login (Status: 200)
/profile (Status: 302)
/files (Status: 302)
/users (Status: 302)




Questions:

1.What port number has a web server with a CMS running?

ans: 8000

2.What is the username we can find in the CMS?
ans:bolt

3.What is the password we can find for the username?
ans:boltadmin123

4.What version of the CMS is installed on the server? (Ex: Name 1.1.1)

ans: 3.7.1

5. There's an exploit for a previous version of this CMS, which allows authenticated RCE. Find it on Exploit DB. What's its EDB-ID?

ans:48296
6.Metasploit recently added an exploit module for this vulnerability. What's the full path for this exploit? (Ex: exploit/....)

Note: If you can't find the exploit module its most likely because your metasploit isn't updated. Run `apt update` then `apt install metasploit-framework`

ans:exploit/unix/webapp/bolt_authenticated_rce

7.Set the LHOST, LPORT, RHOST, USERNAME, PASSWORD in msfconsole before running the exploit

8.Look for flag.txt inside the machine.

ans:THM{wh0_d035nt_l0ve5_b0l7_r1gh7?}




Info found:

Hey guys,

i suppose this is our secret forum right? I posted my first message for our readers today but there seems to be a lot of freespace out there. Please check it out! my password is boltadmin123 just incase you need it!

Regards,

Jake (Admin)