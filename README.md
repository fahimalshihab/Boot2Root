# Boot2Root Cheatsheet

## **Target Information**
- **Machine Name:** [Machine Name]
- **IP Address:** [Target IP]
- **Difficulty Level:** [Easy/Medium/Hard]

---

## **Enumeration**
### **Network Scanning**
```bash
nmap -sn [Subnet]                  # Ping sweep for live hosts
nmap -sC -sV -oN nmap_initial.txt [Target IP]  # Basic scan
nmap -A -p- -oN nmap_full.txt [Target IP]     # Aggressive scan
```

### **Web Enumeration**
```bash
gobuster dir -u http://[Target IP] -w /usr/share/wordlists/dirb/common.txt -x .php,.txt,.html
subfinder -d [Target Domain]     # Find subdomains
amass enum -d [Target Domain]    # Active enumeration
```

### **Service Enumeration**
```bash
hydra -l [username] -P [wordlist] [service]://[Target IP]  # Brute-force login
searchsploit [Service/Version]  # Check for known vulnerabilities
```

---

## **Exploitation**
### **Command Injection Tests**
```bash
ls; cat /etc/passwd  # Test command injection
```

### **Exploit Execution**
```bash
[Exploit command]
```

---

## **Post-Exploitation & Privilege Escalation**
### **Basic System Info & User Privileges**
```bash
whoami && id
uname -a
sudo -l  # Check sudo privileges
```

### **Privilege Escalation Techniques**
#### **Sudo Misconfiguration**
```bash
sudo -l
sudo [binary] [command]
```
#### **Kernel Exploits**
```bash
linux-exploit-suggester
```
#### **SUID Exploits**
```bash
find / -perm -4000 -type f 2>/dev/null
```
#### **Spawning a TTY Shell**
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## **Root Flag & Cleanup**
### **Capture the Flag**
```bash
cat /root/root.txt
```

### **Cover Your Tracks**
```bash
history -c && logout
```

---

**End of Cheatsheet.**

