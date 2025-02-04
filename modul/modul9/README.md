# Modul 9: Malware Analysis and Reverse Engineering

## Deskripsi
Modul ini membahas teknik-teknik analisis malware dan reverse engineering. Siswa akan mempelajari metodologi analisis malware, tools yang digunakan, teknik reverse engineering, dan cara mengamankan sistem dari malware.

## Persyaratan
1. **Hardware**
   - Processor: Intel Core i7/AMD Ryzen 7 atau lebih tinggi
   - RAM: Minimal 16GB
   - Storage: 100GB free space
   - Virtualization support

2. **Software**
   - VMware Workstation Pro
   - IDA Pro/Ghidra
   - Debuggers
   - Analysis tools

3. **Pengetahuan**
   - Assembly language
   - Windows internals
   - Networking concepts
   - Programming skills

## Struktur Modul

### 1. Materi Pembelajaran
- [MATERI.md](MATERI.md) - Materi lengkap pembelajaran
- [BAHAN_AJAR.md](BAHAN_AJAR.md) - Panduan pengajaran untuk instruktur

### 2. Praktikum
- [/praktikum/lab9](../praktikum/lab9) - Panduan dan tugas praktikum

### 3. Referensi
- Practical Malware Analysis
- The Art of Memory Forensics
- Reversing: Secrets of Reverse Engineering
- Malware Analyst's Cookbook

## Penggunaan

1. **Persiapan**
   ```bash
   # Clone repository
   git clone https://github.com/idiarso4/MODUL-SIJA-ETHICAL-HACKING.git
   
   # Masuk ke direktori modul
   cd MODUL-SIJA-ETHICAL-HACKING/modul/modul9
   ```

2. **Setup Lab**
   ```bash
   # Install analysis tools
   sudo apt install -y \
       radare2 \
       gdb \
       strace \
       ltrace

   # Install Python tools
   pip3 install \
       pefile \
       yara-python \
       volatility3
   ```

3. **Akses Materi**
   - Buka MATERI.md untuk materi pembelajaran
   - Ikuti panduan di BAHAN_AJAR.md untuk pengajaran
   - Lakukan praktikum sesuai instruksi di /praktikum/lab9

## Development Environment

### 1. Analysis Tools
```bash
# Install additional tools
sudo apt install -y \
    binwalk \
    foremost \
    volatility \
    wireshark
```

### 2. Development Tools
```bash
# Install development tools
sudo apt install -y \
    build-essential \
    python3-dev \
    libssl-dev \
    libffi-dev
```

## Kontribusi
Silakan berkontribusi dengan membuat pull request untuk:
- Analysis tools
- Sample malware (benign)
- Analysis scripts
- Documentation

## Keamanan
- Gunakan isolated lab environment
- Jangan jalankan malware di sistem produksi
- Ikuti proper handling procedures
- Dokumentasikan semua aktivitas

## Lisensi
Materi ini dilisensikan di bawah [MIT License](LICENSE)

## Kontak
- Email: [idiarso4@gmail.com](mailto:idiarso4@gmail.com)
- GitHub: [@idiarso4](https://github.com/idiarso4)
