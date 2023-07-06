Ip Address:10.10.244.99

Nmap:
PORT     STATE SERVICE       REASON  VERSION
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: GAIA
|   NetBIOS_Domain_Name: GAIA
|   NetBIOS_Computer_Name: GAIA
|   DNS_Domain_Name: GAIA
|   DNS_Computer_Name: GAIA
|   Product_Version: 10.0.17763
|_  System_Time: 2022-02-04T10:08:05+00:00
| ssl-cert: Subject: commonName=GAIA
| Issuer: commonName=GAIA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-02-03T10:04:58
| Not valid after:  2022-08-05T10:04:58
| MD5:   bd9a b2bb 5940 13f0 ce75 cac9 c47b ef27
| SHA-1: 1f0e 0c85 b0d2 fc43 251f b256 3c6c a0eb 8d2b 4ce6
| -----BEGIN CERTIFICATE-----
| MIICzDCCAbSgAwIBAgIQUcBEpeZj4qxN9UnNtLg1wDANBgkqhkiG9w0BAQsFADAP
| MQ0wCwYDVQQDEwRHQUlBMB4XDTIyMDIwMzEwMDQ1OFoXDTIyMDgwNTEwMDQ1OFow
| DzENMAsGA1UEAxMER0FJQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
| ALzQdBaEGbIgP4Zf8t1//N1VS7/r19S/RkkH1kYWGQECrNJ09LylI5gHBKE2xiSz
| orpHEONbIeqhCgafiqABgy9RSXThqsg9+xaBPkXLUBxKmxUefnp8D5UjwIBAdGOK
| yNVCa8Z/6d82zVXs++wvBfBo6slWuY40v18jsASyhOVlliNECHO35gpGGz5S69iP
| /86IraeIFHCtq7KGbUxKM8ZZE1oXLC3pPWBw+uAgrVkBWmzIDhXCbKsxQXqdwvzy
| RJxKMUq9JEUYOUDO5QV8hGtV/1185e2vgBx/vc6eeQpBTy4l82iYDywPGP6XDxhN
| JUtzlkMQqUms6U/PYhdKztECAwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYBBQUHAwEw
| CwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBCwUAA4IBAQAODLUqNkxM1poZKLRTtKFn
| OhTP33lDbcoy7cyQvVefsEGJZ8fyZUH/mtIfZv7+Z6aBnd25vLGg4pgeMcnK+OmC
| o7+w06C3aXyBgqOqoH1MPPJecMOkt2DU5o5HjZDuHLgokG1s2ytZxn6YVLSGs4sq
| 6oEhvqKaZkZygzLcOj9xnMolWeyFletl0bVgk66ru5ET5zkP6SHuVrQhxQmXGrGg
| j1WEdJt7wZWMDjY7ZGF0h8C6vHl32/PqKJ7YnQXYEyaZWUik3uvQ/QP3CfkdYP7h
| ns+WA4hDT349ZciVl5dBx9NAmZj1IZe8+wKfGm1ew+2neqCgLQfV3OXyCeGjPEK4
|_-----END CERTIFICATE-----
|_ssl-date: 2022-02-04T10:08:08+00:00; +1s from scanner time.
8080/tcp open  http-proxy    syn-ack
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Type: text/html
|     Content-Length: 177
|     Connection: Keep-Alive
|     <HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD><BODY><H1>404 Not Found</H1>The requested URL nice%20ports%2C/Tri%6Eity.txt%2ebak was not found on this server.<P></BODY></HTML>
|   GetRequest: 
|     HTTP/1.1 401 Access Denied
|     Content-Type: text/html
|     Content-Length: 144
|     Connection: Keep-Alive
|     WWW-Authenticate: Digest realm="ThinVNC", qop="auth", nonce="u/3zeY3G5UDI2D0CjcblQA==", opaque="KfEJDVho0ARADIBUMgO3gZ3np0AX2OiTxA"
|_    <HTML><HEAD><TITLE>401 Access Denied</TITLE></HEAD><BODY><H1>401 Access Denied</H1>The requested URL requires authorization.<P></BODY></HTML>
| http-auth: 
| HTTP/1.1 401 Access Denied\x0D
|_  Digest opaque=ObVYNoMEiiafMiYCpAEi9nHkJeCJWFCpLl nonce=QzZ8g43G5UDI4j0CjcblQA== qop=auth realm=ThinVNC
|_http-favicon: Unknown favicon MD5: CEE00174E844FDFEB7F56192E6EC9F5D
| http-methods: 
|_  Supported Methods: GET POST
|_http-title: 401 Access Denied
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.91%I=7%D=2/4%Time=61FCFAA6%P=x86_64-pc-linux-gnu%r(Get
SF:Request,179,"HTTP/1\.1\x20401\x20Access\x20Denied\r\nContent-Type:\x20t
SF:ext/html\r\nContent-Length:\x20144\r\nConnection:\x20Keep-Alive\r\nWWW-
SF:Authenticate:\x20Digest\x20realm=\"ThinVNC\",\x20qop=\"auth\",\x20nonce
SF:=\"u/3zeY3G5UDI2D0CjcblQA==\",\x20opaque=\"KfEJDVho0ARADIBUMgO3gZ3np0AX
SF:2OiTxA\"\r\n\r\n<HTML><HEAD><TITLE>401\x20Access\x20Denied</TITLE></HEA
SF:D><BODY><H1>401\x20Access\x20Denied</H1>The\x20requested\x20URL\x20\x20
SF:requires\x20authorization\.<P></BODY></HTML>\r\n")%r(FourOhFourRequest,
SF:111,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Type:\x20text/html\r\n
SF:Content-Length:\x20177\r\nConnection:\x20Keep-Alive\r\n\r\n<HTML><HEAD>
SF:<TITLE>404\x20Not\x20Found</TITLE></HEAD><BODY><H1>404\x20Not\x20Found<
SF:/H1>The\x20requested\x20URL\x20nice%20ports%2C/Tri%6Eity\.txt%2ebak\x20
SF:was\x20not\x20found\x20on\x20this\x20server\.<P></BODY></HTML>\r\n");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Try to find what's runing on 8080:
curl 10.10.244.99:8080 -v                                                                                                  130 ⨯
*   Trying 10.10.244.99:8080...
* Connected to 10.10.244.99 (10.10.244.99) port 8080 (#0)
> GET / HTTP/1.1
> Host: 10.10.244.99:8080
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 401 Access Denied
< Content-Type: text/html
< Content-Length: 144
< Connection: Keep-Alive
< WWW-Authenticate: Digest realm="ThinVNC", qop="auth", nonce="gNr3oo3G5UDI4T0CjcblQA==", opaque="uVEDivBoDCvXfVQJHQkN4oRmjvUoI6NmVD"
< 
<HTML><HEAD><TITLE>401 Access Denied</TITLE></HEAD><BODY><H1>401 Access Denied</H1>The requested URL  requires authorization.<P></BODY></HTML>
* Connection #0 to host 10.10.244.99 left intact


Found ThinVNC

run the exploit found on https://github.com/MuirlandOracle/CVE-2019-17662

found Credentials: 

Username:       Atlas
Password:       H0ldUpTheHe@vens

Connect to the RDP
xfreerdp /v:10.10.244.99 /u:Atlas /p:H0ldUpTheHe@vens /cert:ignore +clipboard /dynamic-resolution /drive:share,/tmp
