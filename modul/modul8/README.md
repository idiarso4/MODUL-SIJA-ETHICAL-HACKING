# Modul 8: Cloud Security

## Deskripsi
Modul ini membahas aspek keamanan dalam komputasi awan (cloud computing), termasuk keamanan infrastruktur, data, dan aplikasi cloud. Siswa akan mempelajari best practices dalam mengamankan layanan cloud, manajemen identitas dan akses, serta compliance dan regulasi.

## Persyaratan
1. **Hardware**
   - Processor: Intel Core i5/AMD Ryzen 5 atau lebih tinggi
   - RAM: Minimal 8GB
   - Storage: 50GB free space
   - Stable internet connection

2. **Software**
   - Web browser
   - Cloud CLI tools
   - Security tools
   - Development tools

3. **Accounts**
   - AWS Free Tier
   - Azure Free Account
   - GCP Free Tier
   - GitHub Account

## Struktur Modul

### 1. Materi Pembelajaran
- [MATERI.md](MATERI.md) - Materi lengkap pembelajaran
- [BAHAN_AJAR.md](BAHAN_AJAR.md) - Panduan pengajaran untuk instruktur

### 2. Praktikum
- [/praktikum/lab8](../praktikum/lab8) - Panduan dan tugas praktikum

### 3. Referensi
- Cloud Security Alliance Guidelines
- AWS Security Best Practices
- Azure Security Documentation
- Google Cloud Security Guide

## Penggunaan

1. **Persiapan**
   ```bash
   # Clone repository
   git clone https://github.com/idiarso4/MODUL-SIJA-ETHICAL-HACKING.git
   
   # Masuk ke direktori modul
   cd MODUL-SIJA-ETHICAL-HACKING/modul/modul8
   ```

2. **Setup Lab**
   ```bash
   # Install AWS CLI
   curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
   unzip awscliv2.zip
   sudo ./aws/install

   # Install Azure CLI
   curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

   # Install Google Cloud SDK
   echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
   curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
   sudo apt-get update && sudo apt-get install google-cloud-sdk
   ```

3. **Akses Materi**
   - Buka MATERI.md untuk materi pembelajaran
   - Ikuti panduan di BAHAN_AJAR.md untuk pengajaran
   - Lakukan praktikum sesuai instruksi di /praktikum/lab8

## Development Environment

### 1. Cloud Tools
```bash
# Install security tools
sudo apt install -y \
    terraform \
    ansible \
    kubectl \
    helm
```

### 2. Security Tools
```bash
# Install additional tools
pip install \
    checkov \
    prowler \
    scout-suite \
    cloudsploit
```

## Kontribusi
Silakan berkontribusi dengan membuat pull request untuk:
- Cloud security best practices
- Infrastructure as Code
- Security scripts
- Documentation

## Keamanan
- Gunakan akun cloud terpisah untuk testing
- Jangan simpan credentials di repository
- Monitor resource usage
- Ikuti principle of least privilege

## Lisensi
Materi ini dilisensikan di bawah [MIT License](LICENSE)

## Kontak
- Email: [idiarso4@gmail.com](mailto:idiarso4@gmail.com)
- GitHub: [@idiarso4](https://github.com/idiarso4)
