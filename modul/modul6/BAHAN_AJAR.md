# Bahan Ajar Modul 6: Mobile Application Security

## Deskripsi Modul
Modul ini membahas aspek keamanan aplikasi mobile, mencakup platform Android dan iOS. Siswa akan mempelajari metodologi pengujian keamanan mobile, reverse engineering, analisis malware mobile, dan implementasi security controls pada aplikasi mobile.

## Tujuan Pembelajaran
Setelah menyelesaikan modul ini, siswa diharapkan mampu:
1. Memahami arsitektur keamanan Android dan iOS
2. Melakukan mobile app security testing
3. Menganalisis kerentanan aplikasi mobile
4. Mengimplementasikan security controls
5. Melakukan reverse engineering aplikasi mobile

## Materi Pembelajaran

### 1. Mobile Security Fundamentals
#### A. Android Security
1. Android Architecture
   - Security model
   - Permission system
   - Sandbox mechanism
   - Inter-process communication

2. Android Components
   - Activities
   - Services
   - Broadcast receivers
   - Content providers
   - Intent system

#### B. iOS Security
1. iOS Architecture
   - Security layers
   - App sandbox
   - Code signing
   - Encryption

2. iOS Protection
   - Data protection
   - Keychain services
   - App Transport Security
   - Privacy controls

### 2. Mobile App Analysis
#### A. Static Analysis
1. Android APK Analysis
   - Decompilation
   - Source code review
   - Manifest analysis
   - Resource inspection

2. iOS IPA Analysis
   - Binary analysis
   - Property list files
   - Entitlements
   - Framework inspection

#### B. Dynamic Analysis
1. Runtime Analysis
   - Debugging
   - API monitoring
   - Network traffic
   - Memory analysis

2. Behavioral Analysis
   - User interaction
   - Data flow
   - Permission usage
   - System interaction

### 3. Mobile App Vulnerabilities
#### A. Common Vulnerabilities
1. Client-side Vulnerabilities
   - Insecure data storage
   - Weak cryptography
   - Code injection
   - Authentication bypass

2. Server-side Vulnerabilities
   - API vulnerabilities
   - Backend security
   - Authentication issues
   - Authorization flaws

#### B. Platform-specific Issues
1. Android Issues
   - Intent hijacking
   - Content provider leakage
   - Broadcast theft
   - Root detection bypass

2. iOS Issues
   - Jailbreak detection
   - Keychain vulnerabilities
   - URL scheme abuse
   - Touch ID bypass

### 4. Security Testing
#### A. Testing Methodology
1. OWASP Mobile Testing
   - Architecture testing
   - Data storage
   - Cryptography
   - Authentication
   - Network communication

2. Testing Tools
   - MobSF
   - Drozer
   - Frida
   - Objection

#### B. Penetration Testing
1. Android Testing
   - ADB usage
   - Root detection
   - SSL pinning bypass
   - Hooking methods

2. iOS Testing
   - Jailbreak tools
   - Binary analysis
   - Runtime manipulation
   - Network interception

### 5. Security Implementation
#### A. Secure Development
1. Android Security
   - ProGuard configuration
   - Certificate pinning
   - Encryption implementation
   - Secure storage

2. iOS Security
   - App Transport Security
   - Keychain usage
   - Data protection
   - Code signing

#### B. Best Practices
1. Development Guidelines
   - Input validation
   - Output encoding
   - Authentication
   - Session management

2. Security Controls
   - Root detection
   - SSL pinning
   - Encryption
   - Access control

## Metode Pembelajaran
1. Teori dan Konsep
   - Presentasi
   - Diskusi
   - Case studies
   - Code review

2. Praktikum
   - Lab exercises
   - Tool usage
   - Security testing
   - Implementation

3. Project Work
   - App development
   - Security testing
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
   - Testing skills
   - Implementation

3. Project (30%)
   - App security
   - Testing report
   - Documentation
   - Presentation

## Referensi
1. OWASP Mobile Security Testing Guide
2. Android Security Cookbook
3. iOS Application Security
4. Mobile Application Hacker's Handbook

## Rencana Pembelajaran

### Minggu 1: Mobile Security Fundamentals
- Android architecture
- iOS architecture
- Security models
- Platform security

### Minggu 2: Static Analysis
- APK analysis
- IPA analysis
- Source code review
- Security assessment

### Minggu 3: Dynamic Analysis
- Runtime analysis
- API monitoring
- Traffic analysis
- Behavioral testing

### Minggu 4: Vulnerability Assessment
- Common vulnerabilities
- Platform-specific issues
- Security testing
- Mitigation strategies

### Minggu 5: Security Implementation
- Secure development
- Best practices
- Security controls
- Testing methodology

## Tugas dan Proyek

### 1. Individual Tasks
- Tool mastery
- Security testing
- Documentation
- Presentation

### 2. Group Projects
- App assessment
- Security testing
- Implementation
- Documentation

### 3. Lab Exercises
- Static analysis
- Dynamic analysis
- Security testing
- Implementation

## Appendix

### A. Lab Setup Guide
1. Android Environment
   - Android Studio
   - SDK tools
   - Emulator
   - Testing tools

2. iOS Environment
   - Xcode
   - iOS Simulator
   - Testing tools
   - Development certificates

### B. Security Tools
1. Analysis Tools
   - MobSF
   - Drozer
   - Frida
   - Objection

2. Testing Tools
   - Burp Suite
   - Charles Proxy
   - Wireshark
   - MITM Proxy

### C. Code Examples
1. Android Security
   ```java
   // Encryption
   public class Crypto {
       private static final String AES_MODE = "AES/GCM/NoPadding";
       private static final int IV_LENGTH = 12;
       
       public static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
           byte[] iv = new byte[IV_LENGTH];
           SecureRandom random = new SecureRandom();
           random.nextBytes(iv);
           
           Cipher cipher = Cipher.getInstance(AES_MODE);
           GCMParameterSpec spec = new GCMParameterSpec(128, iv);
           cipher.init(Cipher.ENCRYPT_MODE, key, spec);
           
           byte[] encrypted = cipher.doFinal(data);
           ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encrypted.length);
           byteBuffer.put(iv);
           byteBuffer.put(encrypted);
           
           return byteBuffer.array();
       }
   }
   ```

2. iOS Security
   ```swift
   // Keychain Access
   class KeychainManager {
       static func save(key: String, data: Data) -> OSStatus {
           let query = [
               kSecClass as String: kSecClassGenericPassword,
               kSecAttrAccount as String: key,
               kSecValueData as String: data,
               kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
           ] as [String: Any]
           
           SecItemDelete(query as CFDictionary)
           return SecItemAdd(query as CFDictionary, nil)
       }
       
       static func load(key: String) -> Data? {
           let query = [
               kSecClass as String: kSecClassGenericPassword,
               kSecAttrAccount as String: key,
               kSecReturnData as String: kCFBooleanTrue!,
               kSecMatchLimit as String: kSecMatchLimitOne
           ] as [String: Any]
           
           var dataTypeRef: AnyObject?
           let status: OSStatus = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
           
           if status == noErr {
               return dataTypeRef as? Data
           }
           return nil
       }
   }
   ```

### D. Security Checklists
1. Development Checklist
   - [ ] Input validation
   - [ ] Secure storage
   - [ ] Network security
   - [ ] Authentication
   - [ ] Authorization
   - [ ] Encryption
   - [ ] Code obfuscation
   - [ ] Anti-tampering

2. Testing Checklist
   - [ ] Static analysis
   - [ ] Dynamic analysis
   - [ ] Network testing
   - [ ] Authentication
   - [ ] Authorization
   - [ ] Data storage
   - [ ] Cryptography
   - [ ] Code quality
