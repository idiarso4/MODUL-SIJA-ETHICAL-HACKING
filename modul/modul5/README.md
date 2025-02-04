# Modul 5: Web Application Security

## Deskripsi
Modul ini membahas aspek keamanan aplikasi web secara mendalam, termasuk identifikasi vulnerabilitas, teknik eksploitasi, dan implementasi security controls. Siswa akan mempelajari OWASP Top 10, metode pengujian keamanan web, dan best practices dalam pengembangan aplikasi web yang aman.

## Persyaratan
1. **Hardware**
   - Processor: Intel Core i5/AMD Ryzen 5 atau lebih tinggi
   - RAM: Minimal 8GB
   - Storage: 50GB free space
   - Network: Stable internet connection

2. **Software**
   - Kali Linux/ParrotOS
   - Burp Suite Professional/Community
   - OWASP ZAP
   - Modern web browsers
   - Code editors (VSCode, Sublime)

3. **Pengetahuan**
   - Basic web development
   - HTML, CSS, JavaScript
   - Basic PHP/Python
   - Database concepts

## Struktur Modul

### 1. Materi Pembelajaran
- [MATERI.md](MATERI.md) - Materi lengkap pembelajaran
- [BAHAN_AJAR.md](BAHAN_AJAR.md) - Panduan pengajaran untuk instruktur

### 2. Praktikum
- [/praktikum/lab5](../praktikum/lab5) - Panduan dan tugas praktikum

### 3. Referensi
- OWASP Testing Guide
- Web Application Hacker's Handbook
- Real-World Bug Hunting
- Browser Security Handbook

## Penggunaan

1. **Persiapan**
   ```bash
   # Clone repository
   git clone https://github.com/idiarso4/MODUL-SIJA-ETHICAL-HACKING.git
   
   # Masuk ke direktori modul
   cd MODUL-SIJA-ETHICAL-HACKING/modul/modul5
   ```

2. **Setup Lab**
   ```bash
   # Install dependencies
   sudo apt update
   sudo apt install -y \
       docker.io \
       docker-compose \
       nodejs \
       npm

   # Setup vulnerable apps
   docker-compose up -d
   ```

3. **Akses Materi**
   - Buka MATERI.md untuk materi pembelajaran
   - Ikuti panduan di BAHAN_AJAR.md untuk pengajaran
   - Lakukan praktikum sesuai instruksi di /praktikum/lab5

## Development Environment

### 1. Web Security Tools
```bash
# Install security tools
sudo apt install -y \
    burpsuite \
    zaproxy \
    nikto \
    sqlmap \
    wfuzz \
    dirb
```

### 2. Development Tools
```bash
# Install development tools
sudo apt install -y \
    php \
    mysql-server \
    python3 \
    python3-pip \
    git
```

## Kontribusi
Silakan berkontribusi dengan membuat pull request untuk:
- Penambahan materi
- Perbaikan code examples
- Security tools baru
- Dokumentasi

## Keamanan
- Gunakan lab environment yang terisolasi
- Jangan gunakan tools pada sistem produksi
- Ikuti etika dan regulasi yang berlaku
- Laporkan vulnerabilities yang ditemukan

## Lisensi
Materi ini dilisensikan di bawah [MIT License](LICENSE)

## Kontak
- Email: [idiarso4@gmail.com](mailto:idiarso4@gmail.com)
- GitHub: [@idiarso4](https://github.com/idiarso4)
