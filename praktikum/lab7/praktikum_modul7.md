# Praktikum Modul 7: Network Security and Signal Analysis

## Pendahuluan

Praktikum ini fokus pada aspek praktis keamanan jaringan dan analisis sinyal. Siswa akan mempelajari dan mempraktikkan berbagai teknik untuk monitoring jaringan, analisis protokol, deteksi intrusi, dan keamanan wireless.

## Tujuan Pembelajaran

Setelah menyelesaikan praktikum ini, siswa diharapkan mampu:
1. Menggunakan tools analisis jaringan
2. Melakukan packet capture dan analysis
3. Menganalisis keamanan wireless
4. Mengimplementasikan IDS/IPS
5. Melakukan signal monitoring

## Persiapan Lab Environment

### A. Network Setup

1. **Interface Configuration**
   ```bash
   # Check interfaces
   ip addr show
   
   # Enable monitoring mode
   sudo airmon-ng start wlan0
   
   # Check monitor mode
   iwconfig
   ```

2. **Tool Installation**
   ```bash
   # Install required tools
   sudo apt update
   sudo apt install -y \
       wireshark \
       tcpdump \
       nmap \
       kismet
   ```

### B. Signal Analysis Setup

1. **SDR Configuration**
   ```bash
   # Install SDR tools
   sudo apt install -y \
       gnuradio \
       gqrx-sdr \
       rtl-sdr
   
   # Test SDR device
   rtl_test
   ```

2. **GNU Radio Setup**
   ```bash
   # Start GNU Radio
   gnuradio-companion
   
   # Load sample flow graph
   File -> Open -> sample_analysis.grc
   ```

## Lab 1: Network Protocol Analysis

### A. Packet Capture

1. **Using Wireshark**
   ```bash
   # Start capture
   sudo wireshark
   
   # Select interface
   # Start capture
   # Apply filter: tcp port 80
   ```

2. **Using tcpdump**
   ```bash
   # Capture HTTP traffic
   sudo tcpdump -i eth0 'tcp port 80' -w capture.pcap
   
   # Analyze capture
   tcpdump -r capture.pcap -n
   ```

### B. Protocol Analysis

1. **HTTP Analysis**
   ```bash
   # Filter HTTP traffic
   tshark -r capture.pcap -Y "http"
   
   # Extract HTTP headers
   tshark -r capture.pcap -Y "http" -T fields -e http.host -e http.request.uri
   ```

2. **SSL/TLS Analysis**
   ```bash
   # Capture SSL traffic
   sudo tcpdump -i eth0 'tcp port 443' -w ssl.pcap
   
   # Analyze handshake
   tshark -r ssl.pcap -Y "ssl.handshake"
   ```

## Lab 2: Wireless Security

### A. WiFi Analysis

1. **Network Discovery**
   ```bash
   # Start monitoring
   sudo airodump-ng wlan0mon
   
   # Target specific network
   sudo airodump-ng -c 1 --bssid 00:11:22:33:44:55 -w capture wlan0mon
   ```

2. **WPA Handshake Capture**
   ```bash
   # Capture handshake
   sudo airodump-ng -c 1 --bssid 00:11:22:33:44:55 -w wpa wlan0mon
   
   # Deauth to force handshake
   sudo aireplay-ng -0 1 -a 00:11:22:33:44:55 wlan0mon
   ```

### B. Bluetooth Analysis

1. **Device Discovery**
   ```bash
   # Scan for devices
   sudo hcitool scan
   
   # Get device info
   sudo hcitool info 00:11:22:33:44:55
   ```

2. **Service Discovery**
   ```bash
   # List services
   sdptool browse 00:11:22:33:44:55
   
   # Connect to device
   sudo rfcomm connect 0 00:11:22:33:44:55
   ```

## Lab 3: Signal Analysis

### A. RF Monitoring

1. **Basic SDR Reception**
   ```bash
   # Start GQRX
   gqrx
   
   # Configure frequency
   # Set gain
   # Start reception
   ```

2. **Signal Recording**
   ```bash
   # Record IQ data
   rtl_sdr -f 100M -s 2.4M -n 24M signal.bin
   
   # Convert to complex samples
   sox signal.bin -t raw -r 2.4M -e signed-integer -b 16 signal.wav
   ```

### B. Signal Processing

1. **FFT Analysis**
   ```python
   import numpy as np
   from scipy import signal
   import matplotlib.pyplot as plt

   # Load signal
   data = np.fromfile('signal.bin', dtype=np.complex64)
   
   # Perform FFT
   f, t, Sxx = signal.spectrogram(data, fs=2.4e6)
   
   # Plot spectrogram
   plt.pcolormesh(t, f, 10 * np.log10(Sxx))
   plt.ylabel('Frequency [Hz]')
   plt.xlabel('Time [sec]')
   plt.show()
   ```

2. **Demodulation**
   ```python
   # FM demodulation
   def fm_demod(data):
       # Differentiate phase
       diff = np.diff(np.unwrap(np.angle(data)))
       
       # Normalize
       audio = diff / (2 * np.pi)
       
       return audio
   
   # Demodulate signal
   audio = fm_demod(data)
   ```

## Lab 4: Intrusion Detection

### A. IDS Setup

1. **Snort Configuration**
   ```bash
   # Install Snort
   sudo apt install snort
   
   # Configure network
   sudo nano /etc/snort/snort.conf
   
   # Test configuration
   sudo snort -T -c /etc/snort/snort.conf
   ```

2. **Rule Creation**
   ```bash
   # Create custom rule
   sudo nano /etc/snort/rules/local.rules
   
   # Add rule
   alert tcp any any -> $HOME_NET 80 (msg:"HTTP Traffic"; flow:to_server,established; content:"GET"; http_method; sid:1000001; rev:1;)
   ```

### B. Alert Analysis

1. **Log Monitoring**
   ```bash
   # Monitor alerts
   sudo tail -f /var/log/snort/alert
   
   # Analyze logs
   sudo snort -r /var/log/snort/snort.log.* -n 10
   ```

2. **Alert Processing**
   ```python
   # Parse alerts
   def parse_alerts(logfile):
       alerts = []
       with open(logfile, 'r') as f:
           for line in f:
               if '[**]' in line:
                   alerts.append(line.strip())
       return alerts
   
   # Process alerts
   alerts = parse_alerts('/var/log/snort/alert')
   ```

## Evaluasi

### A. Kriteria Penilaian

1. **Technical Skills (40%)**
   - Tool usage
   - Analysis ability
   - Implementation skills
   - Problem solving

2. **Documentation (30%)**
   - Lab reports
   - Analysis results
   - Findings
   - Recommendations

3. **Analysis (30%)**
   - Protocol understanding
   - Signal analysis
   - Security assessment
   - Mitigation strategies

### B. Deliverables

1. **Lab Report**
   - Setup documentation
   - Analysis results
   - Captured data
   - Findings
   - Recommendations

2. **Presentation**
   - 15 minutes
   - Live demo
   - Q&A session
   - Technical depth

## Referensi

1. Wireshark User Guide
2. Aircrack-ng Documentation
3. GNU Radio Tutorials
4. Snort Manual

## Appendix

### A. Tool Commands

1. **Wireshark**
   ```bash
   # Capture filters
   tcp port 80
   host 192.168.1.1
   
   # Display filters
   http
   tcp.flags.syn == 1
   ```

2. **tcpdump**
   ```bash
   # Basic capture
   tcpdump -i eth0
   
   # Advanced filters
   tcpdump 'tcp[tcpflags] & (tcp-syn) != 0'
   ```

### B. Analysis Scripts

1. **Packet Analysis**
   ```python
   from scapy.all import *

   def analyze_packet(packet):
       if IP in packet:
           print(f"IP src: {packet[IP].src}")
           print(f"IP dst: {packet[IP].dst}")
           
       if TCP in packet:
           print(f"Port src: {packet[TCP].sport}")
           print(f"Port dst: {packet[TCP].dport}")

   # Sniff packets
   sniff(prn=analyze_packet, count=10)
   ```

2. **Signal Analysis**
   ```python
   import numpy as np
   from scipy import signal

   def analyze_spectrum(data, fs):
       f, t, Sxx = signal.spectrogram(data, fs)
       
       # Find peak frequencies
       peak_freqs = f[np.argmax(np.abs(Sxx), axis=0)]
       
       return peak_freqs

   # Analyze recorded signal
   peak_freqs = analyze_spectrum(data, fs=2.4e6)
   ```

### C. Security Checklist

1. **Network Analysis**
   - [ ] Interface setup
   - [ ] Capture filters
   - [ ] Protocol analysis
   - [ ] Traffic patterns
   - [ ] Anomaly detection
   - [ ] Performance metrics
   - [ ] Security assessment
   - [ ] Documentation

2. **Signal Analysis**
   - [ ] SDR setup
   - [ ] Frequency selection
   - [ ] Signal capture
   - [ ] Demodulation
   - [ ] Spectrum analysis
   - [ ] Pattern recognition
   - [ ] Interference detection
   - [ ] Documentation
