ip address: 10.10.164.12

Nmap results: 

ORT     STATE SERVICE       REASON  VERSION
80/tcp   open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  syn-ack Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2021-11-22T10:38:24+00:00
| ssl-cert: Subject: commonName=Relevant
| Issuer: commonName=Relevant
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-11-21T10:37:19
| Not valid after:  2022-05-23T10:37:19
| MD5:   203a c9e0 97e7 96c0 a6cd 1425 e506 f14f
| SHA-1: a8ca f37a 0e5f 6ab6 9cbb 4338 4ffd a795 0846 4010
| -----BEGIN CERTIFICATE-----
| MIIC1DCCAbygAwIBAgIQa8oEI/DmH5BDkmXCeTXkETANBgkqhkiG9w0BAQsFADAT
| MREwDwYDVQQDEwhSZWxldmFudDAeFw0yMTExMjExMDM3MTlaFw0yMjA1MjMxMDM3
| MTlaMBMxETAPBgNVBAMTCFJlbGV2YW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEApP1dGB9igzUPicX7ybbbJZq6LC9+EyBT/PMsfjT23U790dLBGcwg
| af7mBsiyDQGTtljikjgg8TdUytXF8Tl+YwJiWkoUpLXZU3z94zttexcFl1dhn6CB
| lQ5PANtPVKQTDeuntjYXVo8eTpWPbs396UcqcHDby3KZxhSNw7W52KcQ//aBKwzj
| g0K2t23AoNF2rFpVs6+uUj+w8QPvyFyIkR5LV55wO5CB5kcTHcM5/uH4jXsObS9b
| JHxysATD3o5gvwJcB9Z0y4JSjlSbT1ps0nszFCzDzF2qU4vqOfWGvt6jzqePU4Da
| PI8tkvUUS9ZOqu09f9MedogriiQRSnGSnQIDAQABoyQwIjATBgNVHSUEDDAKBggr
| BgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAGU/RkPX+7IN
| 3PLPQGFo6DutLQytKOlCyoiDd9/2ngk67IZF6QoJ4CH8ERr/0+XEtMBzMGy3nSM3
| 8y/reczMuWyyW5G3+LAIUt86ZebLJD9KJxGYrwNSrblciJR2u4Tmr4+24Z68Kjut
| NjKoagHE2cKlqzySnESjNcXpCpI5mqTU/4hdEl94928dcmfwEiuL5eoicFIlIl5j
| qhAm9W/lBYbVTAqXlOST6Obr1Ck4DHXWFhwmBNSzks9xEK4NGvKh5e2RvURr2Ldd
| ZalGIMWgp9ZxKRp1EqP2j+F/wRXVmkO9TNvaPP18D1uh2OaWfnAWHMeGZxCpaA29
| EfXrfFFBm8c=
|_-----END CERTIFICATE-----
|_ssl-date: 2021-11-22T10:39:03+00:00; 0s from scanner time.
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h36m00s, deviation: 3h34m41s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 56198/tcp): CLEAN (Timeout)
|   Check 2 (port 20878/tcp): CLEAN (Timeout)
|   Check 3 (port 50768/udp): CLEAN (Timeout)
|   Check 4 (port 45799/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-11-22T02:38:27-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-11-22T10:38:27
|_  start_date: 2021-11-22T10:37:37




Scaned all ports : nmap -p- -oN allports.txt $Ip

PORT      STATE SERVICE       REASON
80/tcp    open  http          syn-ack
135/tcp   open  msrpc         syn-ack
139/tcp   open  netbios-ssn   syn-ack
445/tcp   open  microsoft-ds  syn-ack
3389/tcp  open  ms-wbt-server syn-ack
49663/tcp open  unknown       syn-ack
49667/tcp open  unknown       syn-ack
49669/tcp open  unknown       syn-ack



Enumarate shares:

smbclient -L 10.10.164.12                                                                                                                                1 ⨯
Enter WORKGROUP\kali's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk      
SMB1 disabled -- no workgroup available


smbclient   \\\\10.10.36.49\\nt4wrksv                                                                                                                                                        1 ⨯
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 25 17:46:04 2020
  ..                                  D        0  Sat Jul 25 17:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020

                7735807 blocks of size 4096. 4945443 blocks available
smb: \> 





Got users from passwords.txt:

Bob - !P@$$W0rD!123 
Bill - Juw4nnaM4n420696969!$$$          



┌──(kali㉿kali)-[~/Practice/tryhackme/Relevant]
└─$ cat passwords.txt                         
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/tryhackme/Relevant]
└─$ echo Qm9iIC0gIVBAJCRXMHJEITEyMw== | base64 -d                               
Bob - !P@$$W0rD!123                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/tryhackme/Relevant]
└─$ echo QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk | base64 -d
Bill - Juw4nnaM4n420696969!$$$                                     






┌──(kali㉿kali)-[~/Practice/tryhackme/Relevant]
└─$ crackmapexec smb 10.10.36.49 -u Bob  -p '!P@$W0rD!123'                                                                                                                                       1 ⨯
SMB         10.10.36.49     445    RELEVANT         [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:RELEVANT) (domain:Relevant) (signing:False) (SMBv1:True)
SMB         10.10.36.49     445    RELEVANT         [-] Relevant\Bob:!P@$W0rD!123 STATUS_LOGON_FAILURE 
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/tryhackme/Relevant]
└─$ crackmapexec smb 10.10.36.49 -u Bill  -p 'Juw4nnaM4n420696969!$$$'
SMB         10.10.36.49     445    RELEVANT         [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:RELEVANT) (domain:Relevant) (signing:False) (SMBv1:True)
SMB         10.10.36.49     445    RELEVANT         [+] Relevant\Bill:Juw4nnaM4n420696969!$$$ 




user flag:     THM{fdk4ka34vk346ksxfr21tg789ktf45}

root flag:     THM{1fk5kf469devly1gl320zafgl345pv}                                                                                                                                              
