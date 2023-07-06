Steel Mountain

ip:10.10.247.207

1.Who is the employee of the month? - bill harper

2.Scan the machine with nmap. What is the other port running a web server on?

nmap -A -vv 10.10.247.207

PORT      STATE SERVICE            REASON  VERSION
80/tcp    open  http               syn-ack Microsoft IIS httpd 8.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc              syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server? syn-ack
| ssl-cert: Subject: commonName=steelmountain
| Issuer: commonName=steelmountain
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2021-11-02T18:39:16
| Not valid after:  2022-05-04T18:39:16
| MD5:   b386 99eb 3a80 c4e7 10ed 47f6 4d74 68f6
| SHA-1: 0ae5 67ef 7dc1 b8db 9640 f3e3 7b66 ebce ed41 5f58
| -----BEGIN CERTIFICATE-----
| MIIC3jCCAcagAwIBAgIQE+2lYmKSBqVJFXZsvG+MDTANBgkqhkiG9w0BAQUFADAY
| MRYwFAYDVQQDEw1zdGVlbG1vdW50YWluMB4XDTIxMTEwMjE4MzkxNloXDTIyMDUw
| NDE4MzkxNlowGDEWMBQGA1UEAxMNc3RlZWxtb3VudGFpbjCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBANnQUa+qASA5+K2N9TcftJjiFC4Rt6lBS+QNbpai
| jV1tt+kPFlSS8X7QAWCYlYE4jVahCV4ENMuGC+p1TM98Wf+6KgRbakuh0vmA3AFj
| pObi/185G7tPyXQ3Q7rnV/Li+eLuWaSl1USLF8+1iwB/N6ink/OzoxbE05IZWDF3
| +ZS6mnzHOUyfXd65v+zg+VmKXHARbEYtsg02Qe9kQnQV71tXxzf2UUgSoyU4XrgK
| 0BFE/nkQnC8JW2Nw5kWwikHtK+/W6DaDo7cx7jJxsw7Nwp2O0eRbP5jyRC9WH0Wy
| sYsed4tH/nFCW/SGyDMH8Y+OgyLH8YpuhyeEaGiJSBITuhsCAwEAAaMkMCIwEwYD
| VR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBBQUAA4IB
| AQBDGFVC958WtO8vIhcVvYOO/ShgE3ycKjSwb7wKFzEvxArSia9tkZ40kNJo/z4A
| kd/LjDCnTS/VdjpfypajfDbem7dSH5VbA20m/o4SsuTC6biksjnuRe/XGdqWgqTt
| 8AwTYYJoUCCyTpljkpPISN7MmUrEAhyIMe3Ulojv412Mg06DbINluNQTKxvlfRUG
| +NTiQqLco4GSyGbE2r3vwKrca0fU9xdYeqV71S504nT2wq7O+z30zAdKLgu2TZzt
| GbEhr3sgXnXq2TyaA+56xw7D6fNizkDdOj06TRxUzmgn8eEEtHGX3sYz01FXcw/x
| eUynTdmiGOV83kX6UAm892Ou
|_-----END CERTIFICATE-----
|_ssl-date: 2021-11-03T19:00:14+00:00; +1s from scanner time.
8080/tcp  open  http               syn-ack HttpFileServer httpd 2.3
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: HFS 2.3
|_http-title: HFS /
49152/tcp open  msrpc              syn-ack Microsoft Windows RPC
49153/tcp open  msrpc              syn-ack Microsoft Windows RPC
49154/tcp open  msrpc              syn-ack Microsoft Windows RPC
49155/tcp open  msrpc              syn-ack Microsoft Windows RPC
49156/tcp open  msrpc              syn-ack Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 02:38:be:81:cc:79 (unknown)
| Names:
|   STEELMOUNTAIN<00>    Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   STEELMOUNTAIN<20>    Flags: <unique><active>
| Statistics:
|   02 38 be 81 cc 79 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 49424/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 47035/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 17349/udp): CLEAN (Timeout)
|   Check 4 (port 18921/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-11-03T19:00:09
|_  start_date: 2021-11-03T18:38:36


3. Take a look at the other web server. What file server is running?

rejetto hhtp file server

4.What is the CVE number to exploit this file server?

2014-6287

5.Use Metasploit to get an initial shell. What is the user flag?

msf6 > search rejetto http file server 2.3

exploit/windows/http/rejetto_hfs_exec

run exploit

Bill Flag:04763b6fcf51fcd7c13abc7db4fd365

"C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"

Root  flag:
9af5f314f57607c00fd09803a587db80