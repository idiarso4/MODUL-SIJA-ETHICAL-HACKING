# Materi Pembelajaran Modul 2
# Fundamental Ethical Hacking

## 1. Pengantar Ethical Hacking

Ethical hacking, atau penetration testing, adalah praktik menguji sistem komputer, jaringan, dan aplikasi web untuk menemukan kerentanan keamanan yang bisa dieksploitasi oleh penyerang jahat. Tujuannya adalah untuk mengidentifikasi dan memperbaiki kelemahan sebelum bisa dimanfaatkan oleh pihak yang tidak bertanggung jawab.

### 1.1 Definisi dan Konsep Dasar

Ethical hacking berbeda dengan hacking ilegal karena dilakukan dengan izin eksplisit dari pemilik sistem dan bertujuan untuk meningkatkan keamanan. Ini seperti seorang ahli kunci yang diminta untuk menguji keamanan sebuah gedung - tujuannya adalah untuk menemukan dan memperbaiki kelemahan, bukan untuk mencuri.

#### Karakteristik Ethical Hacker:
1. **Izin Resmi**
   - Memiliki persetujuan tertulis
   - Bekerja dalam scope yang ditentukan
   - Melaporkan semua temuan

2. **Profesionalisme**
   - Menjaga kerahasiaan
   - Dokumentasi lengkap
   - Tidak merusak sistem

3. **Kompetensi Teknis**
   - Pemahaman sistem mendalam
   - Penguasaan tools
   - Update pengetahuan

### 1.2 Aspek Legal dan Etika

#### 1.2.1 Regulasi di Indonesia

1. **UU ITE dan Ethical Hacking**
   - Pasal 30: Larangan akses ilegal
   - Pasal 31: Larangan intersepsi
   - Pasal 32: Perlindungan data
   - Pengecualian untuk security testing resmi

2. **Batasan Hukum**
   - Scope testing
   - Dokumentasi izin
   - Pelaporan temuan
   - Perlindungan data

3. **Standar Industri**
   - ISO 27001
   - OWASP Testing Guide
   - PTES Framework
   - NIST Guidelines

#### 1.2.2 Kode Etik Ethical Hacker

1. **Prinsip Dasar**
   - Confidentiality
   - Integrity
   - Non-maleficence
   - Professional conduct

2. **Tanggung Jawab**
   - Melindungi data klien
   - Melaporkan temuan
   - Memberikan rekomendasi
   - Menjaga profesionalisme

### 1.3 Metodologi Ethical Hacking

Ethical hacking mengikuti metodologi sistematis untuk memastikan pengujian yang menyeluruh dan profesional.

#### 1.3.1 Reconnaissance (Pengintaian)

1. **Passive Reconnaissance**
   - OSINT (Open Source Intelligence)
   - Whois lookup
   - DNS enumeration
   - Social media research

2. **Active Reconnaissance**
   - Network scanning
   - Port scanning
   - Service identification
   - Version detection

#### 1.3.2 Scanning

1. **Network Scanning**
   - Host discovery
   - Port scanning
   - Service enumeration
   - OS fingerprinting

2. **Vulnerability Scanning**
   - Automated tools
   - Manual verification
   - False positive checking
   - Risk assessment

#### 1.3.3 Gaining Access

1. **Exploitation Techniques**
   - Password attacks
   - Buffer overflows
   - SQL injection
   - Cross-site scripting

2. **Post Exploitation**
   - Privilege escalation
   - Data extraction
   - Lateral movement
   - Persistence

#### 1.3.4 Maintaining Access

1. **Backdoors**
   - Types of backdoors
   - Persistence mechanisms
   - Command & Control
   - Stealth techniques

2. **Covering Tracks**
   - Log cleaning
   - Hiding files
   - Removing evidence
   - Anti-forensics

### 1.4 Tools dan Teknik

#### 1.4.1 Information Gathering Tools

1. **Network Tools**
   - Nmap
   - Wireshark
   - TCPdump
   - Netcat

2. **Web Tools**
   - Burp Suite
   - OWASP ZAP
   - Nikto
   - Dirbuster

#### 1.4.2 Vulnerability Assessment

1. **Automated Scanners**
   - OpenVAS
   - Nessus
   - Acunetix
   - Qualys

2. **Manual Testing Tools**
   - Metasploit
   - SQLmap
   - Hydra
   - John the Ripper

### 1.5 Dokumentasi dan Pelaporan

#### 1.5.1 Struktur Laporan

1. **Executive Summary**
   - Overview
   - Key findings
   - Risk ratings
   - Recommendations

2. **Technical Details**
   - Methodology
   - Tools used
   - Findings detail
   - Proof of concept

#### 1.5.2 Best Practices Pelaporan

1. **Format Laporan**
   - Clear and concise
   - Evidence-based
   - Actionable items
   - Risk prioritization

2. **Rekomendasi**
   - Short term fixes
   - Long term solutions
   - Risk mitigation
   - Security roadmap

## 2. Persiapan Lab Environment

### 2.1 Setup Virtual Lab

#### 2.1.1 VirtualBox Configuration

1. **System Requirements**
   - CPU virtualization support
   - Minimum 8GB RAM
   - 100GB free disk space
   - Network adapter

2. **Network Setup**
   - NAT Network
   - Host-only Network
   - Internal Network
   - Bridged Adapter

#### 2.1.2 Target Machines

1. **Vulnerable VMs**
   - Metasploitable
   - DVWA
   - WebGoat
   - Vulnhub VMs

2. **Windows Lab**
   - Windows Server
   - Windows 10
   - Legacy systems
   - Active Directory

### 2.2 Security Controls

#### 2.2.1 Lab Isolation

1. **Network Segmentation**
   - Separate virtual network
   - No internet access
   - Firewall rules
   - Network monitoring

2. **Safety Measures**
   - Snapshots
   - Backup
   - Reset procedures
   - Incident response

## 3. Hands-on Exercises

### 3.1 Basic Enumeration

#### 3.1.1 Network Scanning
```bash
# Discover hosts
nmap -sn 192.168.1.0/24

# Port scanning
nmap -sS -sV -O 192.168.1.100

# Service enumeration
nmap -sC -sV 192.168.1.100
```

#### 3.1.2 Web Application
```bash
# Directory scanning
gobuster dir -u http://target -w wordlist.txt

# Vulnerability scanning
nikto -h http://target

# SQL injection testing
sqlmap -u "http://target/page.php?id=1"
```

### 3.2 Exploitation Examples

#### 3.2.1 Metasploit Framework
```bash
# Start Metasploit
msfconsole

# Search exploit
search apache_struts

# Set up exploit
use exploit/multi/http/struts2_content_type_ognl

# Configure options
set RHOSTS target
set RPORT 8080
```

#### 3.2.2 Password Attacks
```bash
# Hash cracking
john --wordlist=rockyou.txt hashes.txt

# Network service brute force
hydra -l admin -P wordlist.txt ssh://target
```

## 4. Defense Strategies

### 4.1 Preventive Measures

1. **System Hardening**
   - OS hardening
   - Service hardening
   - Network hardening
   - Application hardening

2. **Security Controls**
   - Access control
   - Authentication
   - Encryption
   - Monitoring

### 4.2 Detection and Response

1. **Monitoring**
   - IDS/IPS
   - Log analysis
   - Network monitoring
   - Behavioral analysis

2. **Incident Response**
   - Preparation
   - Detection
   - Analysis
   - Containment
   - Eradication
   - Recovery

## Kesimpulan

Ethical hacking adalah keterampilan yang membutuhkan kombinasi pengetahuan teknis, pemahaman legal, dan etika profesional. Dengan mengikuti metodologi yang tepat dan mematuhi regulasi yang berlaku, ethical hacker dapat membantu organisasi mengidentifikasi dan memperbaiki kelemahan keamanan sebelum dieksploitasi oleh pihak yang tidak bertanggung jawab.

## Referensi
1. CEH (Certified Ethical Hacker) Manual
2. OWASP Testing Guide v4.0
3. UU ITE dan Regulasi Terkait
4. NIST Special Publication 800-115
5. Penetration Testing Execution Standard (PTES)
