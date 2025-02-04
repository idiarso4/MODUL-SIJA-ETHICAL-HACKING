# Modul 4: Advanced Penetration Testing dan Security Hardening

## Deskripsi
Modul ini membahas teknik-teknik lanjutan dalam penetration testing dan implementasi security hardening. Siswa akan mempelajari metodologi advanced exploitation, post-exploitation, dan cara mengamankan sistem dari serangan-serangan kompleks.

## Persyaratan
1. **Hardware**
   - Processor: Intel Core i7/AMD Ryzen 7 atau lebih tinggi
   - RAM: Minimal 16GB
   - Storage: 100GB free space
   - Network Card: Multiple NICs dengan support mode monitor

2. **Software**
   - Kali Linux (latest version)
   - VMware Workstation Pro
   - Windows Server 2019
   - Active Directory Lab
   - Custom vulnerable machines

3. **Pengetahuan**
   - Pemahaman mendalam tentang jaringan
   - Scripting (Python, PowerShell, Bash)
   - Dasar-dasar exploit development
   - Konsep keamanan sistem

## Struktur Modul

### 1. Materi Pembelajaran
- [MATERI.md](MATERI.md) - Materi lengkap pembelajaran
- [BAHAN_AJAR.md](BAHAN_AJAR.md) - Panduan pengajaran untuk instruktur

### 2. Praktikum
- [/praktikum/lab4](../praktikum/lab4) - Panduan dan tugas praktikum

### 3. Referensi
- Advanced Penetration Testing by Wil Allsopp
- The Hacker Playbook 3 by Peter Kim
- Gray Hat C# by Brandon Perry
- Black Hat Python by Justin Seitz

## Penggunaan

1. **Persiapan**
   ```bash
   # Clone repository
   git clone https://github.com/idiarso4/MODUL-SIJA-ETHICAL-HACKING.git
   
   # Masuk ke direktori modul
   cd MODUL-SIJA-ETHICAL-HACKING/modul/modul4
   ```

2. **Setup Lab**
   ```bash
   # Install dependencies
   sudo apt update
   sudo apt install -y build-essential python3-dev

   # Setup development environment
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Akses Materi**
   - Buka MATERI.md untuk materi pembelajaran
   - Ikuti panduan di BAHAN_AJAR.md untuk pengajaran
   - Lakukan praktikum sesuai instruksi di /praktikum/lab4

## Development Environment

### 1. Tool Development
```bash
# Setup development tools
sudo apt install -y \
    gcc-multilib \
    gdb \
    radare2 \
    python3-pip

# Install Python packages
pip install \
    pwntools \
    capstone \
    keystone-engine \
    ropper
```

### 2. Testing Environment
```bash
# Setup testing VMs
./setup_lab.sh --full
```

## Kontribusi
Silakan berkontribusi dengan membuat pull request untuk:
- Penambahan teknik baru
- Custom tools dan exploits
- Perbaikan dokumentasi
- Security research

## Keamanan
- Gunakan lab environment yang terisolasi
- Jangan gunakan tools atau teknik di luar lab
- Ikuti etika dan regulasi yang berlaku
- Laporkan bug dan vulnerabilities

## Lisensi
Materi ini dilisensikan di bawah [MIT License](LICENSE)

## Kontak
- Email: [idiarso4@gmail.com](mailto:idiarso4@gmail.com)
- GitHub: [@idiarso4](https://github.com/idiarso4)
