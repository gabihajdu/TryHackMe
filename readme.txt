IP: 10.10.157.195

rustscan:

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

nmap:

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c0:d5:41:ee:a4:d0:83:0c:97:0d:75:cc:7b:10:7f:76 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDR9CEnxhm89ZCC+SGhOpO28srSTnL5lQtnqd4NaT7hTT6N1NrRZQ5DoB6cBI+YlaqYe3I4Ud3y7RF3ESms8L21hbpQus2UYxbWOl+/s3muDpZww1nvI5k9oJguQaLG1EroU8tee7yhPID0+285jbk5AZY72pc7NLOMLvFDijArOhj9kIcsPLVTaxzQ6Di+xwXYdiKO0F3Y7GgMMSszIeigvZEDhNnNW0Z1puMYbtTgmvJH6LpzMSEC+32iNRGlvbjebE9Ehh+tGiOuHKXT1uexrt7gbkjp3lJteV5034a7G1t/Vi3JJoj9tMV/CrvgeDDncbT5NNaSA6/ynLLENqSP
|   256 83:82:f9:69:19:7d:0d:5c:53:65:d5:54:f6:45:db:74 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFhf+BTt0YGudpgOROEuqs4YuIhT1ve23uvZkHhN9lYSpK9WcHI2K5IXIi+XgPeSk/VIQLsRUA0kOqbsuoxN+u0=
|   256 4f:91:3e:8b:69:69:09:70:0e:82:26:28:5c:84:71:c9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDkr5yXgnawt7un+3Tf0TJ+sZTrbVIY0TDbitiu2eHpf
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Empline
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

gobuster:

/.hta (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/assets (Status: 301)
/index.html (Status: 200)
/javascript (Status: 301)
/server-status (Status: 403)


after visiting website I found: http://job.empline.thm/
site is running OpenCats
Version 0.9.4 Countach

{
document.getElementById('username').value = 'john@mycompany.net';
document.getElementById('password').value = 'john99';
document.getElementById('loginForm').submit();
}
function defaultLogin()
{
document.getElementById('username').value = 'admin';
document.getElementById('password').value = 'cats';
document.getElementById('loginForm').submit();



fuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://job.empline.thm/FUZZ                                                                                                                130 ⨯

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://job.empline.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 75ms]
# Copyright 2007 James Fisher [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 139ms]
#                       [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 144ms]
                        [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 160ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 181ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 190ms]
# on atleast 2 different hosts [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 196ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 207ms]
# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 212ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 219ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 243ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 256ms]
#                       [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 257ms]
#                       [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 270ms]
#                       [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 278ms]
xml                     [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 72ms]
modules                 [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 71ms]
careers                 [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 71ms]
scripts                 [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 76ms]
upload                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 77ms]
ajax                    [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 71ms]
test                    [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 89ms]
lib                     [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 83ms]
src                     [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 81ms]
db                      [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 70ms]
js                      [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 78ms]
javascript              [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 73ms]
rss                     [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 3795ms]
temp                    [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 73ms]
vendor                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 73ms]
attachments             [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 77ms]
ci                      [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 99ms]
                        [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 93ms]
wsdl                    [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 75ms]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 76ms]
:: Progress: [220560/220560] :: Job [1/1] :: 551 req/sec :: Duration: [0:06:59] :: Errors: 0 ::

upload a php reverse shell

I intercept the reverse shell upload, change the Content-Type and add GIF87a before the code and with repeater send.


read /var/www/opencats/config.php

 Database configuration. */
define('DATABASE_USER', 'james');
define('DATABASE_PASS', 'ng6pUFvsGNtw');
define('DATABASE_HOST', 'localhost');
define('DATABASE_NAME', 'opencats');

use credentials to log in mysql
mysql -h 10.10.157.195 -u james -p
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| opencats           |
+--------------------+
2 rows in set (0.076 sec)

MariaDB [(none)]> use opencats;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [opencats]> show tables;
+--------------------------------------+
| Tables_in_opencats                   |
+--------------------------------------+
| access_level                         |
| activity                             |
| activity_type                        |
| attachment                           |
| calendar_event                       |
| calendar_event_type                  |
| candidate                            |
| candidate_joborder                   |
| candidate_joborder_status            |
| candidate_joborder_status_history    |
| candidate_jobordrer_status_type      |
| candidate_source                     |
| candidate_tag                        |
| career_portal_questionnaire          |
| career_portal_questionnaire_answer   |
| career_portal_questionnaire_history  |
| career_portal_questionnaire_question |
| career_portal_template               |
| career_portal_template_site          |
| company                              |
| company_department                   |
| contact                              |
| data_item_type                       |
| eeo_ethnic_type                      |
| eeo_veteran_type                     |
| email_history                        |
| email_template                       |
| extension_statistics                 |
| extra_field                          |
| extra_field_settings                 |
| feedback                             |
| history                              |
| http_log                             |
| http_log_types                       |
| import                               |
| installtest                          |
| joborder                             |
| module_schema                        |
| mru                                  |
| queue                                |
| saved_list                           |
| saved_list_entry                     |
| saved_search                         |
| settings                             |
| site                                 |
| sph_counter                          |
| system                               |
| tag                                  |
| user                                 |
| user_login                           |
| word_verification                    |
| xml_feed_submits                     |
| xml_feeds                            |
| zipcodes                             |
+--------------------------------------+
54 rows in set (0.068 sec)

MariaDB [opencats]> select * from user;



admin          | admin@testdomain.com | b67b5ecc5d8902ba59c65596e4c053ec
george         |                      | 86d0dfda99dbebc424eb4407947356ac |
james          |                      | e53fbdb31890ff3bc129db0e27c473c9 


$ cat /etc/passwd
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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash
mysql:x:111:116:MySQL Server,,,:/nonexistent:/bin/false
george:x:1002:1002::/home/george:/bin/bash


we have george user, use crackstation to crack the hash -> pretonnevippasempre

ssh to george user using pretonnevippasempre

read user flag: 91cb89c70aa2e5ce0e0116dab099078e


PrivESC:

after do some enumeration and upload linpeas, i run this command

george@empline:~$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/local/bin/ruby = cap_chown+ep
george@empline:~$ 


read root flag:74fea7cd0556e9c6f22e6f54bc68f5d5
