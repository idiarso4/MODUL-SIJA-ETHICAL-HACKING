# Bahan Ajar Modul 9: Malware Analysis and Reverse Engineering

## Deskripsi Modul
Modul ini membahas teknik-teknik analisis malware dan reverse engineering. Siswa akan mempelajari metodologi analisis malware, tools yang digunakan, teknik reverse engineering, dan cara mengamankan sistem dari malware.

## Tujuan Pembelajaran
Setelah menyelesaikan modul ini, siswa diharapkan mampu:
1. Memahami konsep dasar malware analysis
2. Menggunakan tools untuk analisis malware
3. Melakukan reverse engineering
4. Mengidentifikasi perilaku malware
5. Menerapkan teknik mitigasi malware

## Materi Pembelajaran

### 1. Malware Analysis Fundamentals
#### A. Types of Malware
1. Classification
   - Virus
   - Worm
   - Trojan
   - Ransomware
   - Spyware
   - Rootkit
   - Botnet
   - Cryptominer

2. Infection Vectors
   - Email attachments
   - Drive-by downloads
   - USB drives
   - Network propagation
   - Social engineering

#### B. Analysis Methods
1. Static Analysis
   - File properties
   - String analysis
   - Header analysis
   - Code analysis
   - Signature detection

2. Dynamic Analysis
   - Behavioral analysis
   - Network monitoring
   - Memory analysis
   - API monitoring
   - System changes

### 2. Analysis Environment
#### A. Lab Setup
1. Virtualization
   - VMware Workstation
   - VirtualBox
   - Sandbox solutions
   - Network isolation

2. Tools Setup
   - Debuggers
   - Disassemblers
   - Network analyzers
   - Memory analyzers
   - System monitors

#### B. Safety Measures
1. Isolation
   - Network isolation
   - Physical isolation
   - Virtual isolation
   - Data containment

2. Protection
   - Snapshots
   - Backups
   - Access controls
   - Monitoring

### 3. Static Analysis
#### A. File Analysis
1. Basic Analysis
   - File hashing
   - File type
   - Metadata
   - Strings extraction

2. Code Analysis
   - PE structure
   - Import/Export tables
   - Section analysis
   - Resource analysis

#### B. Disassembly
1. Assembly Code
   - x86 architecture
   - Common instructions
   - Control flow
   - Function analysis

2. Code Patterns
   - API calls
   - String references
   - Crypto functions
   - Network operations

### 4. Dynamic Analysis
#### A. Behavioral Analysis
1. System Monitoring
   - Process activity
   - File operations
   - Registry changes
   - Network activity

2. Memory Analysis
   - Memory dumps
   - Process memory
   - Heap analysis
   - Stack analysis

#### B. Network Analysis
1. Traffic Analysis
   - Protocol analysis
   - Command & Control
   - Data exfiltration
   - Network indicators

2. Communication Patterns
   - DNS requests
   - HTTP traffic
   - Encrypted comms
   - Peer connections

### 5. Reverse Engineering
#### A. Code Analysis
1. Debugging
   - Breakpoints
   - Step execution
   - Memory inspection
   - Register analysis

2. Decompilation
   - Source recovery
   - Control flow
   - Data flow
   - API usage

#### B. Anti-Analysis Techniques
1. Obfuscation
   - Code obfuscation
   - String encryption
   - Anti-debugging
   - Anti-VM

2. Evasion Methods
   - Packing
   - Encryption
   - Polymorphism
   - Metamorphism

## Metode Pembelajaran
1. Teori dan Konsep
   - Presentasi
   - Diskusi
   - Case studies
   - Demonstrations

2. Praktikum
   - Lab exercises
   - Tool usage
   - Analysis practice
   - Documentation

3. Project Work
   - Malware analysis
   - Tool development
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
   - Analysis report
   - Tool development
   - Documentation
   - Presentation

## Referensi
1. Practical Malware Analysis
2. The Art of Memory Forensics
3. Reversing: Secrets of Reverse Engineering
4. Malware Analyst's Cookbook

## Rencana Pembelajaran

### Minggu 1: Fundamentals
- Malware types
- Analysis methods
- Lab setup
- Safety measures

### Minggu 2: Static Analysis
- File analysis
- Code analysis
- Disassembly
- Pattern recognition

### Minggu 3: Dynamic Analysis
- Behavioral analysis
- Memory analysis
- Network analysis
- System monitoring

### Minggu 4: Reverse Engineering
- Debugging
- Decompilation
- Anti-analysis
- Evasion techniques

### Minggu 5: Advanced Topics
- Advanced analysis
- Tool development
- Automation
- Reporting

## Tugas dan Proyek

### 1. Individual Tasks
- Sample analysis
- Tool usage
- Documentation
- Presentation

### 2. Group Projects
- Analysis automation
- Tool development
- Research paper
- Presentation

### 3. Lab Exercises
- Static analysis
- Dynamic analysis
- Reverse engineering
- Tool development

## Appendix

### A. Lab Setup Guide
1. Analysis Environment
   - Virtual machines
   - Network setup
   - Tool installation
   - Safety measures

2. Tool Configuration
   - Debuggers
   - Disassemblers
   - Monitors
   - Analyzers

### B. Analysis Tools
1. Static Analysis
   - IDA Pro
   - Ghidra
   - PE Explorer
   - Strings

2. Dynamic Analysis
   - Process Monitor
   - Process Explorer
   - Wireshark
   - Memory dumps

### C. Code Examples
1. String Decryption
   ```python
   def decrypt_string(encrypted_data, key):
       decrypted = bytearray()
       for i in range(len(encrypted_data)):
           decrypted.append(encrypted_data[i] ^ key[i % len(key)])
       return bytes(decrypted)
   
   # Usage
   encrypted = b'\\x01\\x02\\x03\\x04'
   key = b'KEY'
   decrypted = decrypt_string(encrypted, key)
   ```

2. API Monitoring
   ```python
   from winappdbg import Debug, EventHandler
   
   class ApiHandler(EventHandler):
       def create_process(self, event):
           process = event.get_process()
           print(f"Process created: {process.get_filename()}")
       
       def load_dll(self, event):
           module = event.get_module()
           print(f"DLL loaded: {module.get_filename()}")
   
   # Start monitoring
   debug = Debug(ApiHandler())
   try:
       debug.loop()
   finally:
       debug.stop()
   ```

### D. Analysis Checklists
1. Static Analysis
   - [ ] File properties
   - [ ] Hash values
   - [ ] Strings analysis
   - [ ] PE analysis
   - [ ] Import analysis
   - [ ] Resource analysis
   - [ ] Code analysis
   - [ ] Anti-analysis checks

2. Dynamic Analysis
   - [ ] Process monitoring
   - [ ] File operations
   - [ ] Registry changes
   - [ ] Network activity
   - [ ] Memory analysis
   - [ ] API calls
   - [ ] System changes
   - [ ] Behavioral patterns
