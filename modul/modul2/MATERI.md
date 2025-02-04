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

Metodologi ethical hacking adalah pendekatan sistematis dan terstruktur dalam melakukan pengujian keamanan sistem. Seperti seorang detektif yang mengungkap kasus, seorang ethical hacker harus mengikuti serangkaian langkah yang terorganisir untuk memastikan tidak ada aspek keamanan yang terlewatkan. Metodologi ini terdiri dari beberapa tahap yang saling terkait dan membangun di atas hasil tahap sebelumnya.

#### 1.3.1 Reconnaissance (Pengintaian)

Reconnaissance adalah tahap awal dan paling kritis dalam proses ethical hacking. Pada tahap ini, ethical hacker mengumpulkan sebanyak mungkin informasi tentang target tanpa berinteraksi langsung dengan sistemnya. Ini seperti tahap pengintaian dalam operasi militer - semakin banyak informasi yang dikumpulkan, semakin besar peluang untuk sukses.

**Passive Reconnaissance (Pengintaian Pasif)**

Pengintaian pasif melibatkan pengumpulan informasi tanpa berinteraksi langsung dengan target. Bayangkan seperti mengamati sebuah gedung dari kejauhan - Anda bisa melihat siapa yang masuk-keluar, jadwal operasional, dan pola aktivitas tanpa ketahuan.

Beberapa teknik pengintaian pasif meliputi:
- **OSINT (Open Source Intelligence)**: Mengumpulkan informasi dari sumber publik seperti website perusahaan, media sosial, dan artikel berita. Misalnya, dari LinkedIn bisa didapat informasi tentang teknologi yang digunakan dan struktur organisasi IT.
- **Whois Lookup**: Mencari informasi tentang registrasi domain, termasuk nama registrar, tanggal registrasi, dan informasi kontak teknis.
- **DNS Enumeration**: Menganalisis catatan DNS untuk memahami infrastruktur jaringan target, termasuk subdomain, mail server, dan layanan lainnya.
- **Google Dorking**: Menggunakan operator pencarian khusus untuk menemukan informasi sensitif yang mungkin terekspos di internet.

**Active Reconnaissance (Pengintaian Aktif)**

Berbeda dengan pengintaian pasif, pengintaian aktif melibatkan interaksi langsung dengan sistem target. Ini seperti mencoba membuka pintu-pintu di gedung untuk melihat mana yang terkunci dan mana yang tidak.

Teknik-teknik yang digunakan meliputi:
- **Network Scanning**: Mengidentifikasi host yang aktif dalam jaringan target
- **Port Scanning**: Menemukan port yang terbuka dan layanan yang berjalan
- **Service Identification**: Menentukan versi dan jenis layanan yang berjalan
- **OS Fingerprinting**: Mengidentifikasi sistem operasi yang digunakan

#### 1.3.2 Scanning

Scanning adalah tahap di mana ethical hacker mulai memetakan lebih detail tentang sistem target. Jika reconnaissance adalah seperti melihat gedung dari luar, scanning adalah seperti membuat blueprint detail tentang interior gedung.

**Network Scanning**

Network scanning adalah proses sistematis untuk mengidentifikasi dan menganalisis komponen jaringan yang aktif. Proses ini meliputi:
- **Host Discovery**: Menemukan semua perangkat yang aktif dalam jaringan target menggunakan teknik seperti ping sweep dan ARP scanning.
- **Port Scanning**: Mengidentifikasi port yang terbuka dan protokol yang digunakan, memberikan gambaran tentang layanan yang tersedia.
- **Service Enumeration**: Mengumpulkan informasi detail tentang layanan yang berjalan, termasuk versi dan konfigurasi.
- **OS Fingerprinting**: Mengidentifikasi sistem operasi berdasarkan karakteristik respons jaringan.

**Vulnerability Scanning**

Vulnerability scanning adalah proses otomatis untuk mengidentifikasi kerentanan keamanan dalam sistem. Proses ini seperti memeriksa setiap jendela dan pintu untuk menemukan yang rusak atau tidak terkunci dengan benar.

Komponen utama vulnerability scanning meliputi:
- **Automated Tools**: Penggunaan scanner otomatis seperti Nessus, OpenVAS, atau Qualys untuk menemukan kerentanan umum.
- **Manual Verification**: Verifikasi manual untuk memastikan hasil scan akurat dan menghilangkan false positive.
- **Risk Assessment**: Evaluasi tingkat risiko dari setiap kerentanan yang ditemukan.
- **Prioritization**: Menentukan prioritas perbaikan berdasarkan tingkat risiko dan dampak potensial.

#### 1.3.3 Gaining Access

Gaining Access adalah tahap di mana ethical hacker mencoba memanfaatkan kerentanan yang ditemukan untuk mendapatkan akses ke sistem. Ini adalah tahap yang paling sensitif dan harus dilakukan dengan sangat hati-hati untuk menghindari kerusakan sistem.

**Exploitation Techniques**

Exploitation adalah proses memanfaatkan kerentanan yang ditemukan. Beberapa teknik umum meliputi:
- **Password Attacks**: Mencoba membobol autentikasi melalui brute force, dictionary attack, atau social engineering.
- **Buffer Overflows**: Memanfaatkan kelemahan dalam pengelolaan memori aplikasi.
- **SQL Injection**: Menyisipkan kode SQL berbahaya untuk memanipulasi database.
- **Cross-site Scripting**: Menyisipkan script berbahaya ke dalam halaman web yang akan dieksekusi di browser pengguna.

**Post Exploitation**

Setelah mendapatkan akses awal, ethical hacker akan mencoba:
- **Privilege Escalation**: Meningkatkan level akses dari user biasa menjadi administrator.
- **Data Extraction**: Mengidentifikasi dan mengekstrak data sensitif untuk membuktikan potensi risiko.
- **Lateral Movement**: Bergerak ke sistem lain dalam jaringan.
- **Persistence**: Memastikan akses tetap tersedia untuk pengujian lanjutan.

#### 1.3.4 Maintaining Access

Maintaining Access mendemonstrasikan bagaimana penyerang bisa mempertahankan akses ke sistem yang sudah dikompromikan. Tahap ini penting untuk menunjukkan risiko jangka panjang dari sebuah compromise.

**Backdoors**

Backdoor adalah mekanisme untuk mempertahankan akses ke sistem yang sudah dikompromikan:
- **Types of Backdoors**: Berbagai jenis backdoor seperti shell scripts, rootkits, atau trojans.
- **Persistence Mechanisms**: Teknik untuk memastikan backdoor tetap aktif setelah sistem restart.
- **Command & Control**: Metode untuk mengendalikan sistem yang dikompromikan dari jarak jauh.
- **Stealth Techniques**: Cara menyembunyikan keberadaan backdoor dari deteksi.

**Covering Tracks**

Covering tracks adalah proses menghapus bukti aktivitas penetration testing:
- **Log Cleaning**: Menghapus atau memodifikasi log sistem untuk menghilangkan jejak aktivitas.
- **Hiding Files**: Menyembunyikan file dan tools yang digunakan selama testing.
- **Removing Evidence**: Membersihkan semua artifak yang dibuat selama pengujian.
- **Anti-forensics**: Teknik untuk menghindari analisis forensik.

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
