# Bahan Ajar Modul 7: Network Security and Signal Analysis

## Deskripsi Modul
Modul ini membahas aspek keamanan jaringan dan analisis sinyal, termasuk monitoring jaringan, analisis protokol, deteksi intrusi, dan keamanan wireless. Siswa akan mempelajari teknik-teknik untuk mengamankan jaringan dan menganalisis berbagai jenis sinyal komunikasi.

## Tujuan Pembelajaran
Setelah menyelesaikan modul ini, siswa diharapkan mampu:
1. Memahami konsep dasar keamanan jaringan
2. Melakukan analisis protokol jaringan
3. Mengimplementasikan sistem deteksi intrusi
4. Menganalisis keamanan wireless
5. Menerapkan teknik monitoring jaringan

## Materi Pembelajaran

### 1. Network Security Fundamentals
#### A. Network Architecture
1. OSI Model Review
   - Physical Layer
   - Data Link Layer
   - Network Layer
   - Transport Layer
   - Session Layer
   - Presentation Layer
   - Application Layer

2. TCP/IP Protocol Suite
   - IP addressing
   - Routing protocols
   - Transport protocols
   - Application protocols

#### B. Network Security Concepts
1. Security Principles
   - Confidentiality
   - Integrity
   - Availability
   - Authentication
   - Authorization

2. Security Threats
   - Passive attacks
   - Active attacks
   - Internal threats
   - External threats

### 2. Network Protocol Analysis
#### A. Protocol Analysis
1. Packet Analysis
   - Packet structure
   - Header analysis
   - Payload analysis
   - Protocol fields

2. Protocol Security
   - Protocol vulnerabilities
   - Security mechanisms
   - Attack vectors
   - Defense strategies

#### B. Traffic Analysis
1. Traffic Monitoring
   - Capture methods
   - Analysis tools
   - Traffic patterns
   - Anomaly detection

2. Network Forensics
   - Evidence collection
   - Traffic reconstruction
   - Timeline analysis
   - Incident response

### 3. Wireless Security
#### A. Wireless Protocols
1. WiFi Security
   - WEP
   - WPA/WPA2
   - WPA3
   - Enterprise security

2. Bluetooth Security
   - Pairing mechanisms
   - Authentication
   - Encryption
   - Vulnerabilities

#### B. Wireless Attacks
1. Attack Types
   - Evil twin
   - Deauthentication
   - KRACK attack
   - Bluetooth attacks

2. Defense Mechanisms
   - Encryption
   - Authentication
   - Access control
   - Monitoring

### 4. Signal Analysis
#### A. RF Fundamentals
1. Radio Frequency Basics
   - Frequency bands
   - Modulation types
   - Signal strength
   - Interference

2. Signal Processing
   - Sampling
   - Filtering
   - Demodulation
   - Analysis

#### B. Signal Intelligence
1. Signal Interception
   - Passive collection
   - Active collection
   - Direction finding
   - Signal analysis

2. Counter Measures
   - Signal masking
   - Frequency hopping
   - Spread spectrum
   - Encryption

### 5. Intrusion Detection
#### A. IDS/IPS Systems
1. Detection Methods
   - Signature-based
   - Anomaly-based
   - Hybrid systems
   - Machine learning

2. Response Actions
   - Alerting
   - Blocking
   - Logging
   - Mitigation

#### B. Security Monitoring
1. Log Analysis
   - Log collection
   - Log parsing
   - Pattern matching
   - Correlation

2. Incident Response
   - Detection
   - Analysis
   - Containment
   - Recovery

## Metode Pembelajaran
1. Teori dan Konsep
   - Presentasi
   - Diskusi
   - Case studies
   - Demonstrations

2. Praktikum
   - Lab exercises
   - Tool usage
   - Signal analysis
   - Network monitoring

3. Project Work
   - Network analysis
   - Security implementation
   - Documentation
   - Presentation

## Evaluasi Pembelajaran
1. Teori (30%)
   - Quiz
   - Ujian tertulis
   - Presentasi
   - Documentation

2. Praktik (40%)
   - Lab exercises
   - Tool mastery
   - Analysis skills
   - Implementation

3. Project (30%)
   - Network security
   - Signal analysis
   - Documentation
   - Presentation

## Referensi
1. Network Security Essentials
2. Practical Packet Analysis
3. Wireless Security Handbook
4. RF Signals and Systems

## Rencana Pembelajaran

### Minggu 1: Network Security
- Network architecture
- Security principles
- Protocol analysis
- Traffic monitoring

### Minggu 2: Wireless Security
- WiFi security
- Bluetooth security
- Attack types
- Defense mechanisms

### Minggu 3: Signal Analysis
- RF fundamentals
- Signal processing
- Signal intelligence
- Counter measures

### Minggu 4: Intrusion Detection
- IDS/IPS systems
- Detection methods
- Log analysis
- Incident response

### Minggu 5: Security Implementation
- Security controls
- Monitoring systems
- Analysis tools
- Best practices

## Tugas dan Proyek

### 1. Individual Tasks
- Protocol analysis
- Signal monitoring
- Security testing
- Documentation

### 2. Group Projects
- Network assessment
- Security implementation
- Signal analysis
- Documentation

### 3. Lab Exercises
- Packet capture
- Signal analysis
- Security testing
- Tool usage

## Appendix

### A. Lab Setup Guide
1. Network Environment
   - Network cards
   - Wireless adapters
   - SDR hardware
   - Analysis tools

2. Software Tools
   - Wireshark
   - Kismet
   - GNU Radio
   - Security tools

### B. Security Tools
1. Network Tools
   - Wireshark
   - tcpdump
   - nmap
   - netcat

2. Wireless Tools
   - Aircrack-ng
   - Kismet
   - WiFite
   - BlueZ

### C. Code Examples
1. Packet Analysis
   ```python
   from scapy.all import *

   def packet_callback(packet):
       if packet.haslayer(TCP):
           print(f"Source IP: {packet[IP].src}")
           print(f"Destination IP: {packet[IP].dst}")
           print(f"Source Port: {packet[TCP].sport}")
           print(f"Destination Port: {packet[TCP].dport}")

   # Start sniffing
   sniff(prn=packet_callback, filter="tcp", count=10)
   ```

2. Signal Processing
   ```python
   import numpy as np
   from scipy import signal

   def analyze_signal(data, fs):
       # Perform FFT
       f, t, Sxx = signal.spectrogram(data, fs)
       
       # Calculate power spectrum
       power = np.abs(Sxx)**2
       
       # Find peak frequencies
       peak_freqs = f[np.argmax(power, axis=0)]
       
       return peak_freqs, power
   ```

### D. Security Checklists
1. Network Security
   - [ ] Access control
   - [ ] Encryption
   - [ ] Monitoring
   - [ ] Logging
   - [ ] IDS/IPS
   - [ ] Firewalls
   - [ ] Updates
   - [ ] Backups

2. Signal Security
   - [ ] Encryption
   - [ ] Authentication
   - [ ] Frequency management
   - [ ] Power control
   - [ ] Interference detection
   - [ ] Signal monitoring
   - [ ] Direction finding
   - [ ] Counter measures
