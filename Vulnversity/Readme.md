# Vulnversity

Ip = 10.10.133.115

## Namp
`nmap -sC -sV 10.10.133.115`

```
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 5a:4f:fc:b8:c8:76:1c:b5:85:1c:ac:b2:86:41:1c:5a (RSA)
|   256 ac:9d:ec:44:61:0c:28:85:00:88:e9:68:e9:d0:cb:3d (ECDSA)
|_  256 30:50:cb:70:5a:86:57:22:cb:52:d9:36:34:dc:a5:58 (ED25519)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
```

Here 3333 is the http

Lets find directory

## gobuster
`gobuster dir -u http://10.10.6.80:3333 -w /home/iftx/Desktop/Hacking/Recon/wordlist/common.txt .php,.txt,.js,.html`


```
/css                  (Status: 301) [Size: 313] [--> http://10.10.6.80:3333/css/]
/images               (Status: 301) [Size: 316] [--> http://10.10.6.80:3333/images/]
/internal             (Status: 301) [Size: 318] [--> http://10.10.6.80:3333/internal/]
/js                   (Status: 301) [Size: 312] [--> http://10.10.6.80:3333/js/]
```
http://10.10.6.80:3333/internal/
 got a file upload option where i upload a reverse shell and gain the shell

