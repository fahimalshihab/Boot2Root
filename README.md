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
gobuster dir -e -u http://10.10.181.27 -w /home/iftx/Desktop/Room/wordlist/common.txt -x .php,.txt,.js,.html
subfinder -d [Target Domain]     # Find subdomains
amass enum -d [Target Domain]    # Active enumeration
```

### **Service Enumeration**
```bash
hydra -l jan -P /home/iftx/Desktop/Room/wordlist/rockyou.txt 10.10.181.27 ssh

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

