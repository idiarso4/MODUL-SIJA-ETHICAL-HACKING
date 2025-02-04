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
