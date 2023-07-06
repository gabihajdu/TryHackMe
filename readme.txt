Lookback IP: 10.10.78.149


rustscan:
PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack
443/tcp  open  https         syn-ack
3389/tcp open  ms-wbt-server syn-ack


nmap:
PORT     STATE SERVICE       REASON  VERSION
80/tcp   open  http          syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
443/tcp  open  https?        syn-ack
| ssl-cert: Subject: commonName=WIN-12OUO7A66M7
| Subject Alternative Name: DNS:WIN-12OUO7A66M7, DNS:WIN-12OUO7A66M7.thm.local
| Issuer: commonName=WIN-12OUO7A66M7
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-01-25T21:34:02
| Not valid after:  2028-01-25T21:34:02
| MD5:   84e0 805f 3667 c38f d820 4e7c 1da0 4215
| SHA-1: 0845 8fd9 d9bf c4c6 48db 1f82 d3e7 324e a924 52d7
| -----BEGIN CERTIFICATE-----
| MIIDKjCCAhKgAwIBAgIQTm2IqMBJs7RKv49wp456pzANBgkqhkiG9w0BAQUFADAa
| MRgwFgYDVQQDEw9XSU4tMTJPVU83QTY2TTcwHhcNMjMwMTI1MjEzNDAyWhcNMjgw
| MTI1MjEzNDAyWjAaMRgwFgYDVQQDEw9XSU4tMTJPVU83QTY2TTcwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDS7xdfJC7zHZQtxk7LNxq1DQaaapFZsRId
| 66AbvRCYdvTISToxEDYEprkrIU0YIbB9DzvOYQ23X3F3Y7ylUXRsd0yq3lVX86gD
| KtWAChKB9ph0VERYqOXoM5Aaej15todacRmqVgX8lbkK37qVPLz9g7n8VfgrJii9
| zl1Mm8i17s1KERY9aIyxrYecU1dBCX+R4foMHETB7i0yTtG0H+6MAykoTJSJcX+C
| Mx5QTASgGQXpgRSzUy5SSkJlLasyZ+WVnji6ShZWC3/dHUED0cO+AFna2NFQIASa
| fWGXXGnhaCLXctm9dDUnq2eg/+AfkJQNbn5eKIGsBYXDG7tfAqFNAgMBAAGjbDBq
| MA4GA1UdDwEB/wQEAwIFoDA1BgNVHREELjAsgg9XSU4tMTJPVU83QTY2TTeCGVdJ
| Ti0xMk9VTzdBNjZNNy50aG0ubG9jYWwwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYD
| VR0TAQH/BAIwADANBgkqhkiG9w0BAQUFAAOCAQEAPV5SA6om07FjNj3mlpTBJMxI
| 8aOECGirP6f7w5pFqYZ/8TP3ZL2o9Iy2ZzgipcvO0t71IAxHswFv2NN551wNkfie
| ZlcZSzsep/ym+EVRADLeyuDTt5T3aRq4n6EO4DQN0iyczisChAieFFi7FNXJerft
| uAQlqIrqvmpvMlMoin/TLv1Wg4QRXvUk5J4gI8q0DNQt7/bk8DUaHrumq7AP5jym
| wUf2+fSq4nPyB/kW39ftUKiJU/bzmEf4gMozeXTQhzkpFRTgSO+9sRTmiTsk6UMz
| l3WZLZr4/d/H5dnN0b/3k7CcuoFlmZjSKhnIcPQfXBEUIf5dE7pS7BaqVMooYQ==
|_-----END CERTIFICATE-----
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: THM
|   NetBIOS_Domain_Name: THM
|   NetBIOS_Computer_Name: WIN-12OUO7A66M7
|   DNS_Domain_Name: thm.local
|   DNS_Computer_Name: WIN-12OUO7A66M7.thm.local
|   DNS_Tree_Name: thm.local
|   Product_Version: 10.0.17763
|_  System_Time: 2023-03-22T10:11:46+00:00
| ssl-cert: Subject: commonName=WIN-12OUO7A66M7.thm.local
| Issuer: commonName=WIN-12OUO7A66M7.thm.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-01-25T21:12:51
| Not valid after:  2023-07-27T21:12:51
| MD5:   dce9 a019 0d34 ca24 01bd b215 7440 9c9d
| SHA-1: d55a 03f1 992d f334 8059 47f9 90eb 25be 4092 cbf0
| -----BEGIN CERTIFICATE-----
| MIIC9jCCAd6gAwIBAgIQVVEvN1hoxopPxcxgdQbcKzANBgkqhkiG9w0BAQsFADAk
| MSIwIAYDVQQDExlXSU4tMTJPVU83QTY2TTcudGhtLmxvY2FsMB4XDTIzMDEyNTIx
| MTI1MVoXDTIzMDcyNzIxMTI1MVowJDEiMCAGA1UEAxMZV0lOLTEyT1VPN0E2Nk03
| LnRobS5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANCg6Tls
| nrbpOjmP7oy5Ncw+r/Q+Pab6Q4GaHQBCE+gD5XGim9S71LVrxf942NzVSL1ebc3k
| cC+AweAlzaS8AphN+ZbULdLN0hEamafEV0y3ZsYrQBPdqHXg9c4wk7TubmbzU6zY
| fABPXkXQE4nNlJPnlOsaiTCXhuPFLxKLABZ1DLWmFFBLZMC1j88Rb4Pc/BBENYY3
| 8nJIGJi9F44Eq/BDTUiIXCpc6tRkaWclPPB3qVHGOufSkisaWIPYhTIcrHYSHpYO
| MrWqYeJGMuvOdfzXThupfyB9E2ESRM/VZvRzU9cy63Fa5W0fcI4FPmb3SRfQLcHz
| NV5qqMePSSO8FT0CAwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0P
| BAQDAgQwMA0GCSqGSIb3DQEBCwUAA4IBAQAYMi75E8iMGYhCufi02kwo7Q4Q4iSj
| x/Qkme3u+mji8LCeKP7ustS0piVYRZmQlu7IYgeQSHJLqdOquh1cUOpFq+Dc0XX6
| g+wnhCT1qrl+VQz4MfXBh0KwLLWPvLWHJIno+ZKSVgnD/Thsn3UR3AHjG/mr43PS
| PEV1TXqyDyeG3Z0l/z7qfqHXxttdoxVB5VHl2tg0dCf8llmrmhYjEpAi/KC3Hlra
| kxjulcfLKTaUSRytiv//q+WSQIhNvMCGI2UxWiXcLAcv+aIHsUdIGCPrzhnIVCOA
| YCAqzbCtd181CJrW9mlBaiUX6H5yONtSxdZLFFmOsY/rnqOJarElTpQT
|_-----END CERTIFICATE-----
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
