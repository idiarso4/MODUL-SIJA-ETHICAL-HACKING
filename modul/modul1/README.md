# Modul 1: Dasar Keamanan Informasi dan Pengenalan Kali Linux

## Tujuan Pembelajaran
Setelah menyelesaikan modul ini, peserta akan mampu:
1. Memahami konsep dasar keamanan informasi
2. Menjelaskan prinsip CIA dalam keamanan informasi
3. Menginstal dan mengkonfigurasi Kali Linux
4. Menggunakan perintah dasar terminal Linux
5. Mengelola package dan repository di Kali Linux

## 1. Pengertian Keamanan Informasi

Keamanan informasi adalah perlindungan terhadap informasi dari berbagai ancaman untuk:
- Memastikan kelangsungan bisnis
- Meminimalkan risiko bisnis
- Memaksimalkan pengembalian investasi
- Meningkatkan peluang bisnis

### Aspek-aspek Keamanan Informasi:
1. **Physical Security**: Keamanan fisik perangkat dan infrastruktur
2. **Network Security**: Keamanan jaringan komunikasi
3. **Application Security**: Keamanan pada level aplikasi
4. **Operational Security**: Keamanan dalam prosedur operasional

## 2. Prinsip CIA (Confidentiality, Integrity, Availability)

### 2.1 Confidentiality (Kerahasiaan)
- Menjamin informasi hanya dapat diakses oleh pihak yang berwenang
- Implementasi:
  - Enkripsi data
  - Access control
  - Authentication
  - Authorization

### 2.2 Integrity (Integritas)
- Memastikan data tidak diubah secara tidak sah
- Implementasi:
  - Digital signatures
  - Checksums
  - Version control
  - Backup systems

### 2.3 Availability (Ketersediaan)
- Menjamin akses terhadap informasi saat dibutuhkan
- Implementasi:
  - Redundancy
  - Backup systems
  - Disaster recovery
  - Business continuity planning

## 3. Pengenalan Kali Linux

### 3.1 Sejarah dan Perkembangan
- Asal usul dari BackTrack Linux
- Dikembangkan oleh Offensive Security
- Berbasis Debian
- Fokus pada penetration testing dan security auditing

### 3.2 Arsitektur Kali Linux
- Kernel Linux
- Package management system
- Desktop environment
- Security tools collection

### 3.3 Instalasi dan Konfigurasi Dasar
1. **Persyaratan Sistem**:
   - Minimum 2GB RAM (4GB recommended)
   - 20GB hard disk space
   - USB/DVD boot support
   - Internet connection

2. **Metode Instalasi**:
   - Live USB
   - Virtual Machine
   - Hard disk installation
   - Dual boot setup

### 3.4 Manajemen Repository
```bash
# Update repository
sudo apt update

# Upgrade sistem
sudo apt upgrade

# Menambah repository
sudo nano /etc/apt/sources.list

# Install package
sudo apt install [nama-package]
```

### 3.5 Terminal Commands Dasar
```bash
# Navigasi
pwd     # Print working directory
ls      # List files
cd      # Change directory
mkdir   # Make directory
rm      # Remove file/directory

# File operations
cp      # Copy
mv      # Move/rename
cat     # View file content
nano    # Text editor
chmod   # Change permissions

# System information
uname   # System information
top     # Process viewer
df      # Disk usage
free    # Memory usage
```

### 3.6 Package Management
```bash
# APT commands
apt search [package]    # Search for package
apt show [package]      # Show package details
apt install [package]   # Install package
apt remove [package]    # Remove package
apt autoremove         # Remove unused dependencies

# DPKG commands
dpkg -i [package.deb]  # Install .deb package
dpkg -l               # List installed packages
dpkg -r [package]     # Remove package
```

## Praktikum

### Lab 1: Instalasi Kali Linux
- Mempersiapkan media instalasi
- Konfigurasi BIOS/UEFI
- Proses instalasi
- Konfigurasi post-installation

### Lab 2: Dasar Terminal Linux
- Navigasi file system
- File dan directory management
- Permission management
- Process management

### Lab 3: Package Management
- Repository management
- Package installation
- System update dan upgrade
- Troubleshooting

## Evaluasi
1. Quiz tentang konsep keamanan informasi
2. Praktik penggunaan terminal commands
3. Tugas konfigurasi sistem Kali Linux

## Referensi
1. Official Kali Linux Documentation
2. The Linux Command Line (William Shotts)
3. CompTIA Security+ Study Guide
4. NIST Cybersecurity Framework
