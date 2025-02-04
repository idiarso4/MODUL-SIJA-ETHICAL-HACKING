# Bahan Ajar Modul 5: Web Application Security

## Deskripsi Modul
Modul ini membahas aspek keamanan aplikasi web secara mendalam, termasuk identifikasi vulnerabilitas, teknik eksploitasi, dan implementasi security controls. Siswa akan mempelajari OWASP Top 10, metode pengujian keamanan web, dan best practices dalam pengembangan aplikasi web yang aman.

## Tujuan Pembelajaran
Setelah menyelesaikan modul ini, siswa diharapkan mampu:
1. Memahami OWASP Top 10 dan implikasinya
2. Mengidentifikasi dan mengeksploitasi vulnerabilitas web
3. Menerapkan security controls dalam aplikasi web
4. Melakukan web application security testing
5. Mengimplementasikan secure coding practices

## Materi Pembelajaran

### 1. Web Application Security Fundamentals
#### A. Web Architecture
1. HTTP/HTTPS Protocol
   - Request/Response cycle
   - Headers dan methods
   - Status codes
   - Cookies dan sessions

2. Web Technologies
   - Frontend (HTML, CSS, JavaScript)
   - Backend (PHP, Python, Java)
   - Databases (MySQL, MongoDB)
   - Web servers (Apache, Nginx)

#### B. OWASP Top 10
1. Overview
   - Injection
   - Broken Authentication
   - Sensitive Data Exposure
   - XML External Entities (XXE)
   - Broken Access Control
   - Security Misconfiguration
   - Cross-Site Scripting (XSS)
   - Insecure Deserialization
   - Using Components with Known Vulnerabilities
   - Insufficient Logging & Monitoring

2. Risk Assessment
   - Impact analysis
   - Likelihood assessment
   - Risk rating
   - Mitigation strategies

### 2. Web Vulnerabilities and Exploitation
#### A. Injection Attacks
1. SQL Injection
   - Basic injection
   - Union-based
   - Error-based
   - Blind injection
   - Time-based injection

2. Command Injection
   - OS command injection
   - Code injection
   - Template injection
   - Prevention techniques

#### B. Authentication Attacks
1. Authentication Bypass
   - Brute force
   - Credential stuffing
   - Session hijacking
   - OAuth vulnerabilities

2. Session Management
   - Session fixation
   - Session prediction
   - Cookie attacks
   - Token security

### 3. Cross-Site Attacks
#### A. Cross-Site Scripting (XSS)
1. Types of XSS
   - Reflected XSS
   - Stored XSS
   - DOM-based XSS
   - Prevention methods

2. XSS Exploitation
   - Payload development
   - Cookie stealing
   - Keylogging
   - Phishing attacks

#### B. Cross-Site Request Forgery
1. CSRF Mechanics
   - Attack vectors
   - Token bypass
   - Cookie manipulation
   - Prevention techniques

2. Advanced CSRF
   - Same-origin policy
   - CORS configuration
   - Token validation
   - Defense in depth

### 4. Security Controls Implementation
#### A. Input Validation
1. Client-side Validation
   - JavaScript validation
   - HTML5 controls
   - Form validation
   - Sanitization

2. Server-side Validation
   - Data filtering
   - Type checking
   - Whitelisting
   - Regular expressions

#### B. Output Encoding
1. HTML Encoding
   - Character encoding
   - Context-aware encoding
   - Entity encoding
   - URL encoding

2. Security Headers
   - Content Security Policy
   - X-Frame-Options
   - HSTS
   - Cookie security

### 5. Secure Development Practices
#### A. Secure Coding
1. Code Review
   - Static analysis
   - Dynamic analysis
   - Manual review
   - Security testing

2. Security Framework
   - Authentication frameworks
   - Authorization systems
   - Encryption libraries
   - Security controls

#### B. Security Testing
1. Testing Methodology
   - Unit testing
   - Integration testing
   - Penetration testing
   - Security scanning

2. Automated Testing
   - DAST tools
   - SAST tools
   - Security scanners
   - CI/CD integration

## Metode Pembelajaran
1. Teori dan Konsep
   - Presentasi
   - Diskusi
   - Case studies
   - Code review

2. Praktikum
   - Lab exercises
   - CTF challenges
   - Code development
   - Security testing

3. Project Work
   - Secure application development
   - Vulnerability assessment
   - Security implementation
   - Documentation

## Evaluasi Pembelajaran
1. Teori (30%)
   - Quiz
   - Ujian tertulis
   - Presentasi
   - Documentation

2. Praktik (40%)
   - Lab exercises
   - CTF challenges
   - Code review
   - Security testing

3. Project (30%)
   - Application development
   - Security implementation
   - Documentation
   - Presentation

## Referensi
1. OWASP Testing Guide
2. Web Application Hacker's Handbook
3. Real-World Bug Hunting
4. Web Security Testing Cookbook
5. Browser Security Handbook
6. ModSecurity Handbook

## Rencana Pembelajaran

### Minggu 1: Web Security Fundamentals
- Web architecture
- OWASP Top 10
- HTTP/HTTPS
- Basic vulnerabilities

### Minggu 2: Injection Attacks
- SQL injection
- Command injection
- Code injection
- Prevention techniques

### Minggu 3: Authentication & Session
- Authentication bypass
- Session management
- Token security
- Access control

### Minggu 4: Cross-Site Attacks
- XSS types
- CSRF attacks
- Security headers
- Prevention methods

### Minggu 5: Secure Development
- Secure coding
- Security testing
- Automated tools
- Best practices

## Tugas dan Proyek

### 1. Individual Tasks
- Vulnerability research
- Security testing
- Code review
- Documentation

### 2. Group Projects
- Secure application
- Security assessment
- Implementation
- Presentation

### 3. Lab Exercises
- OWASP labs
- CTF challenges
- Code development
- Security testing

## Appendix

### A. Lab Setup Guide
1. Development Environment
   - Web servers
   - Databases
   - Testing tools
   - Security scanners

2. Testing Environment
   - Vulnerable applications
   - Testing frameworks
   - Security tools
   - Documentation

### B. Security Tools
1. Web Proxies
   - Burp Suite
   - OWASP ZAP
   - Fiddler
   - Charles Proxy

2. Security Scanners
   - Acunetix
   - Netsparker
   - Nikto
   - w3af

### C. Code Examples
1. Secure Implementation
   ```php
   // Input validation
   function validateInput($input) {
       return htmlspecialchars(strip_tags($input));
   }

   // Prepared statements
   $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
   $stmt->execute([$id]);
   ```

2. Security Headers
   ```php
   // Security headers
   header("Content-Security-Policy: default-src 'self'");
   header("X-Frame-Options: DENY");
   header("X-XSS-Protection: 1; mode=block");
   header("X-Content-Type-Options: nosniff");
   ```

### D. Security Checklists
1. Development Checklist
   - [ ] Input validation
   - [ ] Output encoding
   - [ ] Authentication
   - [ ] Session management
   - [ ] Access control
   - [ ] Error handling
   - [ ] Logging
   - [ ] Security headers

2. Testing Checklist
   - [ ] Authentication testing
   - [ ] Session testing
   - [ ] Access control
   - [ ] Input validation
   - [ ] Error handling
   - [ ] Security headers
   - [ ] Encryption
   - [ ] Business logic
