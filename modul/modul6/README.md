# Modul 6: Mobile Application Security

## Deskripsi
Modul ini membahas aspek keamanan aplikasi mobile, mencakup platform Android dan iOS. Siswa akan mempelajari metodologi pengujian keamanan mobile, reverse engineering, analisis malware mobile, dan implementasi security controls pada aplikasi mobile.

## Persyaratan
1. **Hardware**
   - Processor: Intel Core i5/AMD Ryzen 5 atau lebih tinggi
   - RAM: Minimal 16GB
   - Storage: 100GB free space
   - USB debugging support

2. **Software**
   - Android Studio
   - Xcode (untuk macOS)
   - Mobile testing tools
   - Virtualization software

3. **Pengetahuan**
   - Basic mobile development
   - Java/Kotlin/Swift basics
   - Network concepts
   - Basic security

## Struktur Modul

### 1. Materi Pembelajaran
- [MATERI.md](MATERI.md) - Materi lengkap pembelajaran
- [BAHAN_AJAR.md](BAHAN_AJAR.md) - Panduan pengajaran untuk instruktur

### 2. Praktikum
- [/praktikum/lab6](../praktikum/lab6) - Panduan dan tugas praktikum

### 3. Referensi
- OWASP Mobile Security Testing Guide
- Android Security Cookbook
- iOS Application Security
- Mobile Application Hacker's Handbook

## Penggunaan

1. **Persiapan**
   ```bash
   # Clone repository
   git clone https://github.com/idiarso4/MODUL-SIJA-ETHICAL-HACKING.git
   
   # Masuk ke direktori modul
   cd MODUL-SIJA-ETHICAL-HACKING/modul/modul6
   ```

2. **Setup Lab**
   ```bash
   # Install Android tools
   sudo apt install -y \
       android-tools-adb \
       android-tools-fastboot

   # Install testing tools
   pip3 install \
       frida-tools \
       objection
   ```

3. **Akses Materi**
   - Buka MATERI.md untuk materi pembelajaran
   - Ikuti panduan di BAHAN_AJAR.md untuk pengajaran
   - Lakukan praktikum sesuai instruksi di /praktikum/lab6

## Development Environment

### 1. Android Tools
```bash
# Install Android tools
sudo apt install -y \
    android-studio \
    gradle \
    openjdk-11-jdk
```

### 2. Security Tools
```bash
# Install security tools
sudo apt install -y \
    apktool \
    dex2jar \
    jd-gui \
    mobsf
```

## Kontribusi
Silakan berkontribusi dengan membuat pull request untuk:
- Mobile security tools
- Testing scripts
- Lab exercises
- Documentation

## Keamanan
- Gunakan device/emulator khusus untuk testing
- Jangan install tools berbahaya di device pribadi
- Ikuti etika dan regulasi yang berlaku
- Laporkan vulnerabilities yang ditemukan

## Lisensi
Materi ini dilisensikan di bawah [MIT License](LICENSE)

## Kontak
- Email: [idiarso4@gmail.com](mailto:idiarso4@gmail.com)
- GitHub: [@idiarso4](https://github.com/idiarso4)
