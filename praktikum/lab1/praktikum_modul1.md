# Praktikum Modul 1: Instalasi dan Konfigurasi Dasar Kali Linux

## Lab 1: Instalasi Kali Linux

### Tujuan
- Melakukan instalasi Kali Linux dalam virtual machine
- Mengkonfigurasi pengaturan dasar sistem
- Memahami proses boot dan partitioning

### Alat dan Bahan
1. Computer dengan spesifikasi minimal:
   - Processor: Intel Core i5 atau AMD Ryzen 5
   - RAM: 8GB
   - Storage: 100GB free space
2. VirtualBox/VMware Workstation
3. ISO Kali Linux terbaru
4. Internet connection

### Langkah-langkah

#### A. Persiapan Virtual Machine
1. Buka VirtualBox/VMware
2. Buat VM baru dengan spesifikasi:
   - Name: Kali Linux
   - Type: Linux
   - Version: Debian 64-bit
   - Memory: 4096 MB
   - Hard disk: 60 GB (dynamically allocated)
   - Network: NAT + Host-only adapter

#### B. Instalasi Kali Linux
1. Mount ISO Kali Linux
2. Boot dari ISO
3. Pilih "Graphical Install"
4. Ikuti wizard instalasi:
   - Pilih bahasa dan keyboard layout
   - Konfigurasi network
   - Setup users dan passwords
   - Partitioning
   - Install system
   - Install GRUB bootloader

#### C. Konfigurasi Post-Installation
1. Update sources.list
2. Update dan upgrade sistem
3. Install guest additions
4. Konfigurasi network
5. Setup shared folders

### Tugas
1. Dokumentasikan proses instalasi
2. Screenshot setiap langkah penting
3. Catat kendala yang ditemui dan solusinya

## Lab 2: Dasar Terminal Linux

### Tujuan
- Memahami struktur filesystem Linux
- Menguasai perintah dasar terminal
- Mampu melakukan manajemen file dan direktori

### Latihan

#### A. Navigasi Filesystem
```bash
# Eksplorasi direktori
pwd
ls -la
cd /
ls
cd /home
cd ~
cd ..
cd -

# Mencari file
find / -name "*.txt"
locate password
which python
```

#### B. File dan Directory Management
```bash
# Membuat dan menghapus direktori
mkdir test_dir
mkdir -p parent/child/grandchild
rmdir test_dir
rm -rf parent

# File operations
touch test.txt
cp test.txt backup.txt
mv backup.txt new_name.txt
cat test.txt
less /etc/passwd
head -n 5 /etc/passwd
tail -f /var/log/syslog
```

#### C. Permission Management
```bash
# View permissions
ls -l test.txt

# Change permissions
chmod 644 test.txt
chmod u+x script.sh
chmod go-w test.txt

# Change ownership
chown user:group file.txt
```

### Tugas
1. Buat struktur direktori untuk project
2. Praktikkan semua perintah di atas
3. Dokumentasikan hasil setiap perintah

## Lab 3: Package Management

### Tujuan
- Memahami sistem package management
- Mampu menginstall dan remove software
- Mengelola repository

### Latihan

#### A. Repository Management
```bash
# Edit sources.list
sudo nano /etc/apt/sources.list

# Update repository
sudo apt update
```

#### B. Package Installation
```bash
# Search package
apt search wireshark

# Show package info
apt show wireshark

# Install package
sudo apt install wireshark

# Remove package
sudo apt remove wireshark
sudo apt autoremove
```

#### C. System Update
```bash
# Update package list
sudo apt update

# Upgrade packages
sudo apt upgrade

# Distribution upgrade
sudo apt dist-upgrade
```

### Tugas
1. Tambahkan repository baru
2. Install 5 tools security
3. Dokumentasikan proses dan hasil

## Laporan Praktikum

### Format Laporan
1. Pendahuluan
2. Dasar Teori
3. Langkah Kerja
4. Hasil dan Pembahasan
5. Kesimpulan
6. Referensi

### Kriteria Penilaian
1. Kelengkapan dokumentasi (30%)
2. Ketepatan langkah kerja (40%)
3. Analisis hasil (20%)
4. Format laporan (10%)

## Praktikum Modul 1: Dasar Keamanan Informasi dan Pengenalan Kali Linux

## Pendahuluan

Praktikum ini dirancang untuk memberikan pemahaman fundamental tentang keamanan informasi dan pengenalan praktis terhadap sistem operasi Kali Linux. Melalui serangkaian latihan hands-on, siswa akan mempelajari konsep dasar keamanan informasi dan mengembangkan keterampilan dalam menggunakan tools dasar di Kali Linux.

## Tujuan Pembelajaran

Setelah menyelesaikan praktikum ini, siswa diharapkan mampu:
1. Memahami dan menerapkan prinsip dasar keamanan informasi (CIA Triad)
2. Menginstal dan mengkonfigurasi Kali Linux dengan benar
3. Menggunakan perintah dasar Linux dan tools keamanan
4. Mengidentifikasi dan menganalisis ancaman keamanan dasar
5. Menerapkan langkah-langkah pengamanan sistem dasar

## Persiapan Lab Environment

### A. Instalasi VirtualBox

1. **Download dan Instalasi**
   ```bash
   # Download VirtualBox dari website resmi
   https://www.virtualbox.org/wiki/Downloads

   # Verifikasi instalasi di PowerShell
   VBoxManage --version
   ```

2. **Konfigurasi Sistem**
   - Aktifkan virtualisasi di BIOS/UEFI
   - Alokasikan minimal 50GB storage
   - Pastikan RAM minimal 8GB
   - Aktifkan Network Adapter

### B. Instalasi Kali Linux

1. **Download ISO**
   ```bash
   # Download dari website resmi
   https://www.kali.org/get-kali/#kali-virtual-machines

   # Verifikasi checksum
   sha256sum kali-linux-2024.1-installer-amd64.iso
   ```

2. **Konfigurasi VM**
   ```bash
   # Spesifikasi rekomendasi
   RAM: 4GB
   CPU: 2 cores
   Storage: 50GB
   Network: NAT + Host-only
   ```

3. **Post-Installation Setup**
   ```bash
   # Update sistem
   sudo apt update
   sudo apt upgrade -y

   # Install tools tambahan
   sudo apt install -y \
       virtualbox-guest-x11 \
       terminator \
       vim \
       git
   ```

## Lab 1: Pengenalan Command Line Interface

### A. Navigasi Sistem File

1. **Perintah Dasar**
   ```bash
   # Navigasi direktori
   pwd                     # Cek direktori saat ini
   ls -la                  # List semua file termasuk hidden
   cd /path/to/directory   # Pindah direktori
   
   # Manipulasi file
   touch file.txt          # Buat file kosong
   mkdir directory         # Buat direktori
   cp source dest          # Copy file
   mv source dest          # Pindah/rename file
   rm file                 # Hapus file
   rm -rf directory        # Hapus direktori dan isinya
   ```

2. **File Permissions**
   ```bash
   # Lihat permissions
   ls -l file.txt
   
   # Ubah permissions
   chmod 755 file.txt      # rwxr-xr-x
   chmod u+x file.txt      # Tambah execute untuk user
   
   # Ubah kepemilikan
   chown user:group file.txt
   ```

### B. Text Editing

1. **Vim Basic**
   ```bash
   # Buka file
   vim file.txt
   
   # Mode dasar
   i    # Insert mode
   esc  # Normal mode
   :w   # Save
   :q   # Quit
   :wq  # Save and quit
   ```

2. **Nano Editor**
   ```bash
   # Buka file
   nano file.txt
   
   # Shortcut umum
   Ctrl + O  # Save
   Ctrl + X  # Exit
   Ctrl + K  # Cut line
   Ctrl + U  # Paste line
   ```

## Lab 2: Networking Basics

### A. Konfigurasi Network

1. **Interface Management**
   ```bash
   # Lihat interface
   ip addr show
   ifconfig -a
   
   # Enable/disable interface
   sudo ifconfig eth0 up
   sudo ifconfig eth0 down
   ```

2. **IP Configuration**
   ```bash
   # Set IP statis
   sudo ifconfig eth0 192.168.1.100 netmask 255.255.255.0
   
   # DHCP client
   sudo dhclient eth0
   ```

### B. Network Testing

1. **Connectivity Test**
   ```bash
   # Ping test
   ping -c 4 8.8.8.8
   
   # Traceroute
   traceroute google.com
   
   # DNS lookup
   nslookup google.com
   dig google.com
   ```

2. **Port Scanning Basic**
   ```bash
   # Netcat port scan
   nc -zv 192.168.1.1 80
   
   # Simple Nmap scan
   nmap -sP 192.168.1.0/24
   ```

## Lab 3: Keamanan Sistem Dasar

### A. User Management

1. **User Administration**
   ```bash
   # Buat user baru
   sudo useradd -m username
   sudo passwd username
   
   # Modifikasi user
   sudo usermod -aG sudo username
   sudo userdel -r username
   ```

2. **Group Management**
   ```bash
   # Buat dan kelola group
   sudo groupadd groupname
   sudo groupdel groupname
   sudo gpasswd -a username groupname
   ```

### B. System Hardening

1. **Update Management**
   ```bash
   # Update repository
   sudo apt update
   
   # Upgrade packages
   sudo apt upgrade -y
   
   # Remove unused packages
   sudo apt autoremove
   ```

2. **Service Management**
   ```bash
   # Cek status service
   systemctl status ssh
   
   # Enable/disable service
   sudo systemctl enable ssh
   sudo systemctl disable ssh
   
   # Start/stop service
   sudo systemctl start ssh
   sudo systemctl stop ssh
   ```

## Lab 4: Monitoring dan Logging

### A. System Monitoring

1. **Resource Monitoring**
   ```bash
   # Monitor CPU dan memory
   top
   htop
   
   # Disk usage
   df -h
   du -sh /*
   
   # Process monitoring
   ps aux
   pstree
   ```

2. **Network Monitoring**
   ```bash
   # Traffic monitoring
   tcpdump -i eth0
   
   # Bandwidth monitoring
   iftop -i eth0
   
   # Connection status
   netstat -tuln
   ss -tuln
   ```

### B. Log Analysis

1. **System Logs**
   ```bash
   # View system logs
   sudo tail -f /var/log/syslog
   sudo journalctl -f
   
   # Auth logs
   sudo tail -f /var/log/auth.log
   ```

2. **Log Management**
   ```bash
   # Rotate logs
   sudo logrotate -f /etc/logrotate.conf
   
   # Clear logs
   sudo truncate -s 0 /var/log/syslog
   ```

## Lab 5: Backup dan Recovery

### A. Data Backup

1. **File Backup**
   ```bash
   # Archive files
   tar -czvf backup.tar.gz /path/to/files
   
   # Incremental backup
   rsync -av source/ destination/
   ```

2. **System Backup**
   ```bash
   # Create disk image
   sudo dd if=/dev/sda of=/path/to/backup.img
   
   # Backup with clonezilla
   sudo clonezilla
   ```

### B. System Recovery

1. **File Recovery**
   ```bash
   # Restore from tar
   tar -xzvf backup.tar.gz
   
   # Restore specific files
   rsync -av --include='file.txt' backup/ restore/
   ```

2. **System Restore**
   ```bash
   # Restore disk image
   sudo dd if=backup.img of=/dev/sda
   
   # Boot repair
   sudo boot-repair
   ```

## Evaluasi

### A. Kriteria Penilaian

1. **Kemampuan Teknis (40%)**
   - Penggunaan command line
   - Konfigurasi sistem
   - Troubleshooting
   - Implementasi keamanan

2. **Dokumentasi (30%)**
   - Laporan praktikum
   - Screenshot hasil
   - Penjelasan proses
   - Analisis hasil

3. **Keaktifan (30%)**
   - Partisipasi lab
   - Inisiatif
   - Kerja tim
   - Problem solving

### B. Deliverables

1. **Laporan Praktikum**
   - Format: PDF
   - Minimal 15 halaman
   - Include screenshots
   - Include command outputs

2. **Presentasi**
   - 10 menit presentasi
   - 5 menit demo
   - 5 menit Q&A
   - Slide deck

## Referensi

1. Linux Command Line and Shell Scripting Bible
2. The Linux Command Line by William Shotts
3. Kali Linux Revealed
4. CompTIA Linux+ Study Guide
5. NIST Special Publication 800-53
6. CIS Benchmarks for Linux

## Appendix

### A. Troubleshooting Guide

1. **VirtualBox Issues**
   ```bash
   # Fix kernel modules
   sudo /sbin/vboxconfig
   
   # Fix shared folders
   sudo usermod -aG vboxsf $USER
   ```

2. **Network Issues**
   ```bash
   # Reset networking
   sudo systemctl restart NetworkManager
   
   # Clear DNS cache
   sudo systemd-resolve --flush-caches
   ```

### B. Command Cheat Sheet

1. **File Operations**
   ```bash
   find / -name filename    # Find files
   grep -r "text" /path     # Search in files
   awk '{print $1}' file    # Text processing
   sed 's/old/new/g' file   # Text substitution
   ```

2. **System Admin**
   ```bash
   sudo !!                  # Repeat last command with sudo
   history | grep command   # Search command history
   alias ll='ls -la'        # Create command alias
   export PATH=$PATH:/path  # Add to PATH
   ```

### C. Security Checklist

1. **System Hardening**
   - [ ] Update sistem
   - [ ] Configure firewall
   - [ ] Disable unused services
   - [ ] Set strong passwords
   - [ ] Configure SSH security
   - [ ] Enable system logging
   - [ ] Regular backups
   - [ ] Monitor system resources

2. **Network Security**
   - [ ] Change default passwords
   - [ ] Disable unused ports
   - [ ] Configure network firewall
   - [ ] Enable secure protocols
   - [ ] Monitor network traffic
   - [ ] Regular security updates
   - [ ] Document network layout
   - [ ] Test network security
