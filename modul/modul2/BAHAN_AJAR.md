# Bahan Ajar Modul 2
## Fundamental Ethical Hacking dengan Kali Linux

### Identitas Modul
- **Mata Pelajaran**: Keamanan Informasi
- **Kelas**: XI SIJA
- **Semester**: 1
- **Durasi**: 6 x 45 menit (3 pertemuan)

### A. Tujuan Pembelajaran
Setelah mengikuti pembelajaran ini, siswa dapat:
1. Memahami konsep dan metodologi ethical hacking
2. Membedakan jenis-jenis hacker dan motivasinya
3. Mengkonfigurasi lingkungan pengujian yang aman
4. Menerapkan metodologi pengujian keamanan
5. Menggunakan tools dasar ethical hacking

### B. Materi Pembelajaran

#### 1. Pengantar Ethical Hacking
##### 1.1 Definisi Ethical Hacking
- Pengertian ethical hacking
- Perbedaan dengan cyber crime
- Ruang lingkup kerja ethical hacker
- Tanggung jawab ethical hacker

##### 1.2 Jenis-jenis Hacker
1. **White Hat Hacker**
   - Motivasi dan tujuan
   - Area kerja
   - Sertifikasi profesional
   - Karir dan prospek

2. **Grey Hat Hacker**
   - Karakteristik
   - Batasan etika
   - Potensi risiko
   - Contoh kasus

3. **Black Hat Hacker**
   - Motivasi kriminal
   - Dampak negatif
   - Konsekuensi hukum
   - Studi kasus

#### 2. Metodologi Ethical Hacking
##### 2.1 Fase Pengujian
1. **Reconnaissance**
   - Passive gathering
   - Active gathering
   - Footprinting
   - OSINT

2. **Scanning**
   - Network scanning
   - Vulnerability scanning
   - Port scanning
   - Service enumeration

3. **Gaining Access**
   - Exploitation
   - Password attacks
   - Social engineering
   - Web attacks

4. **Maintaining Access**
   - Backdoors
   - Rootkits
   - Trojans
   - Persistence

5. **Covering Tracks**
   - Log cleaning
   - Hiding files
   - Tunneling
   - Reporting

##### 2.2 Standar dan Framework
- OSSTMM
- PTES
- OWASP
- NIST Framework

#### 3. Setup Lingkungan Lab
##### 3.1 Virtualisasi
1. **VirtualBox Setup**
   - Instalasi VirtualBox
   - Konfigurasi jaringan
   - Snapshot management
   - Resource allocation

2. **Kali Linux VM**
   - System requirements
   - Network adapters
   - Shared folders
   - Performance tuning

3. **Target VMs**
   - Metasploitable
   - DVWA
   - Vulnhub VMs
   - Windows lab machines

##### 3.2 Network Configuration
1. **Network Types**
   - NAT
   - Bridge
   - Host-only
   - Internal network

2. **Security Considerations**
   - Network isolation
   - Internet access
   - Firewall rules
   - MAC spoofing

#### 4. Basic Security Tools
##### 4.1 Information Gathering
- Nmap
- Whois
- Dmitry
- TheHarvester

##### 4.2 Vulnerability Assessment
- OpenVAS
- Nikto
- OWASP ZAP
- WPScan

##### 4.3 Wireless Tools
- Aircrack-ng
- Kismet
- Wifite
- Wireshark

### C. Metode Pembelajaran
1. **Project Based Learning**
   - Mini CTF challenges
   - Lab setup project
   - Tool development

2. **Demonstrasi**
   - Live hacking demos
   - Tool usage
   - Best practices

3. **Diskusi dan Studi Kasus**
   - Ethical debates
   - Case analysis
   - Group discussion

### D. Media dan Alat
1. **Hardware**
   - Laptop/PC (min. i5, 8GB RAM)
   - Wireless adapter
   - USB drive
   - Network switch

2. **Software**
   - VirtualBox/VMware
   - Kali Linux
   - Target VMs
   - Monitoring tools

3. **Materi**
   - Slide presentasi
   - Video tutorial
   - Lab guides
   - Cheat sheets

### E. Kegiatan Pembelajaran

#### Pertemuan 1 (2 x 45 menit)
1. **Pendahuluan (15 menit)**
   - Salam dan doa
   - Presensi
   - Apersepsi: Video kasus cyber attack
   - Motivasi: Peluang karir ethical hacker

2. **Kegiatan Inti (60 menit)**
   - Pengenalan ethical hacking
   - Diskusi jenis-jenis hacker
   - Studi kasus cyber attack
   - Quiz interaktif

3. **Penutup (15 menit)**
   - Rangkuman
   - Refleksi
   - Penugasan: Research cyber attack cases

#### Pertemuan 2 (2 x 45 menit)
1. **Pendahuluan (15 menit)**
   - Review tugas
   - Penjelasan metodologi

2. **Kegiatan Inti (60 menit)**
   - Setup lab environment
   - Konfigurasi VirtualBox
   - Network setup
   - Basic tool testing

3. **Penutup (15 menit)**
   - Troubleshooting
   - Lab completion check
   - Next meeting prep

#### Pertemuan 3 (2 x 45 menit)
1. **Pendahuluan (15 menit)**
   - Lab environment check
   - Tool introduction

2. **Kegiatan Inti (60 menit)**
   - Tool demonstrations
   - Hands-on practice
   - Mini challenges

3. **Penutup (15 menit)**
   - Challenge results
   - Evaluation
   - Next module preview

### F. Penilaian
1. **Teori (30%)**
   - Quiz mingguan
   - Ujian tertulis
   - Presentasi

2. **Praktik (40%)**
   - Lab completion
   - Tool mastery
   - Challenge scores

3. **Proyek (30%)**
   - Lab setup
   - Documentation
   - Team contribution

### G. Referensi
1. CEH (Certified Ethical Hacker) Manual
2. OWASP Testing Guide
3. Kali Linux Revealed
4. The Hacker Playbook 3

### H. Lampiran
1. Lab setup guide
2. Tool cheat sheets
3. Assessment rubrics
4. Challenge scenarios
5. Project templates

### I. Bahan Ajar Modul 2: Metodologi Ethical Hacking

## Deskripsi Modul
Modul ini membahas metodologi ethical hacking secara komprehensif, mulai dari tahap perencanaan hingga pelaporan. Siswa akan mempelajari pendekatan sistematis dalam melakukan pengujian keamanan sistem informasi dengan memperhatikan aspek legal dan etika profesional.

## Tujuan Pembelajaran
Setelah menyelesaikan modul ini, siswa diharapkan mampu:
1. Memahami dan menerapkan metodologi ethical hacking secara sistematis
2. Menggunakan tools dan teknik pengujian keamanan secara bertanggung jawab
3. Melakukan dokumentasi dan pelaporan hasil pengujian secara profesional
4. Mengimplementasikan strategi pertahanan berdasarkan temuan pengujian

## Materi Pembelajaran

### 1. Metodologi Ethical Hacking
Metodologi ethical hacking adalah kerangka kerja sistematis yang memandu proses pengujian keamanan. Bagian ini mencakup:

#### 1.1 Tahapan Pengujian
1. **Reconnaissance (Pengintaian)**
   - Passive Reconnaissance: Pengumpulan informasi tanpa interaksi langsung
   - Active Reconnaissance: Pengumpulan informasi dengan interaksi langsung
   - OSINT (Open Source Intelligence)

2. **Scanning**
   - Network Scanning
   - Vulnerability Scanning
   - Port Scanning
   - Service Enumeration

3. **Gaining Access**
   - Exploitation Techniques
   - Password Attacks
   - Web Application Attacks
   - Social Engineering

4. **Maintaining Access**
   - Backdoors
   - Rootkits
   - Persistence Mechanisms
   - Privilege Escalation

5. **Covering Tracks**
   - Log Cleaning
   - Hiding Files
   - Clearing Evidence
   - Tunneling Techniques

### 2. Tools dan Teknik

#### 2.1 Information Gathering Tools
1. **Network Tools**
   - Penggunaan Nmap untuk network discovery dan security auditing
   - Implementasi Wireshark untuk analisis paket jaringan
   - Pemanfaatan TCPdump untuk packet capture
   - Aplikasi Netcat sebagai network swiss army knife

2. **Web Tools**
   - Burp Suite untuk web application security testing
   - OWASP ZAP untuk automated scanning
   - Nikto untuk web server scanning
   - Dirbuster untuk directory enumeration

#### 2.2 Vulnerability Assessment
1. **Automated Scanners**
   - OpenVAS untuk vulnerability scanning
   - Nessus untuk security assessment
   - Acunetix untuk web vulnerability scanning
   - Qualys untuk cloud-based security

2. **Manual Testing Tools**
   - Metasploit Framework untuk penetration testing
   - SQLmap untuk SQL injection testing
   - Hydra untuk password cracking
   - John the Ripper untuk password auditing

### 3. Lab Environment

#### 3.1 Setup Virtual Lab
1. **VirtualBox Configuration**
   - System requirements dan setup
   - Network configuration
   - Performance optimization
   - Snapshot management

2. **Target Machines**
   - Metasploitable setup
   - DVWA installation
   - WebGoat configuration
   - Windows lab setup

#### 3.2 Security Controls
1. **Lab Isolation**
   - Network segmentation
   - Access controls
   - Monitoring systems
   - Incident response procedures

2. **Documentation**
   - Lab setup documentation
   - Configuration records
   - Test case documentation
   - Results tracking

### 4. Hands-on Exercises

#### 4.1 Basic Enumeration
1. **Network Scanning Exercise**
   ```bash
   # Host Discovery
   nmap -sn 192.168.1.0/24
   
   # Port Scanning
   nmap -sS -sV -O 192.168.1.100
   
   # Service Detection
   nmap -sC -sV 192.168.1.100
   ```

2. **Web Application Testing**
   ```bash
   # Directory Scanning
   gobuster dir -u http://target -w wordlist.txt
   
   # Vulnerability Assessment
   nikto -h http://target
   
   # SQL Injection Testing
   sqlmap -u "http://target/page.php?id=1"
   ```

#### 4.2 Exploitation Practice
1. **Metasploit Framework**
   ```bash
   # Basic Usage
   msfconsole
   search apache_struts
   use exploit/multi/http/struts2_content_type_ognl
   set RHOSTS target
   ```

2. **Password Attacks**
   ```bash
   # Hash Cracking
   john --wordlist=rockyou.txt hashes.txt
   
   # Service Brute Force
   hydra -l admin -P wordlist.txt ssh://target
   ```

## Metode Pembelajaran
1. **Ceramah Interaktif**
   - Presentasi materi
   - Diskusi kelas
   - Tanya jawab
   - Case study analysis

2. **Praktikum**
   - Hands-on lab exercises
   - Tool demonstrations
   - Guided practice
   - Independent exercises

3. **Project-Based Learning**
   - Group projects
   - Individual assignments
   - Lab reports
   - Presentation skills

## Evaluasi
1. **Penilaian Teori**
   - Quiz mingguan
   - Ujian tengah modul
   - Ujian akhir modul
   - Tugas tertulis

2. **Penilaian Praktik**
   - Lab performance
   - Project completion
   - Technical documentation
   - Presentation skills

## Referensi
1. CEH (Certified Ethical Hacker) Manual
2. OWASP Testing Guide v4.0
3. Penetration Testing: A Hands-On Introduction to Hacking
4. The Web Application Hacker's Handbook
5. Network Security Assessment by O'Reilly
6. Metasploit: The Penetration Tester's Guide

## Jadwal
| Minggu | Topik | Aktivitas |
|--------|-------|-----------|
| 1 | Pengenalan Metodologi | Teori & Lab Setup |
| 2 | Information Gathering | Praktik Tools |
| 3 | Vulnerability Assessment | Scanning Exercise |
| 4 | Exploitation Techniques | Lab Practice |
| 5 | Documentation & Defense | Report Writing |

## Persyaratan
1. **Hardware**
   - Laptop/PC dengan minimal 8GB RAM
   - Processor dengan dukungan virtualisasi
   - Storage minimal 100GB free space
   - Network adapter yang kompatibel

2. **Software**
   - VirtualBox terbaru
   - Kali Linux VM
   - Target VMs (Metasploitable, DVWA)
   - Text editor
   - Terminal emulator

3. **Pengetahuan Prasyarat**
   - Dasar jaringan komputer
   - Pemahaman sistem operasi
   - Dasar pemrograman
   - Bahasa Inggris teknis
