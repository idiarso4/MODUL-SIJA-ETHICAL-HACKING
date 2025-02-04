# Praktikum Modul 9: Malware Analysis and Reverse Engineering

## Pendahuluan

Praktikum ini fokus pada teknik-teknik analisis malware dan reverse engineering. Siswa akan mempelajari dan mempraktikkan berbagai metode analisis, penggunaan tools, dan teknik reverse engineering untuk memahami perilaku malware.

## Tujuan Pembelajaran

Setelah menyelesaikan praktikum ini, siswa diharapkan mampu:
1. Melakukan static analysis pada malware
2. Melakukan dynamic analysis
3. Menggunakan tools analisis
4. Melakukan reverse engineering
5. Mendokumentasikan temuan

## Lab Setup

### A. Virtual Environment

1. **VMware Setup**
   ```bash
   # Create analysis VM
   # Windows 10 x64
   RAM: 4GB
   CPU: 2 cores
   HDD: 60GB
   Network: Host-only
   
   # Create REMnux VM
   RAM: 4GB
   CPU: 2 cores
   HDD: 40GB
   Network: Host-only
   ```

2. **Network Configuration**
   ```bash
   # Configure host-only network
   Network: 192.168.56.0/24
   DHCP: Disabled
   
   # Static IP for analysis VM
   IP: 192.168.56.10
   Mask: 255.255.255.0
   Gateway: 192.168.56.1
   
   # Static IP for REMnux
   IP: 192.168.56.20
   Mask: 255.255.255.0
   Gateway: 192.168.56.1
   ```

## Lab 1: Static Analysis

### A. Basic Analysis

1. **File Properties**
   ```powershell
   # Get file hash
   Get-FileHash suspicious.exe -Algorithm SHA256
   
   # Get file type
   file suspicious.exe
   
   # Extract strings
   strings -a suspicious.exe > strings.txt
   ```

2. **PE Analysis**
   ```python
   import pefile
   
   # Open PE file
   pe = pefile.PE('suspicious.exe')
   
   # Print sections
   for section in pe.sections:
       print(section.Name.decode().rstrip('\x00'))
       print(f"Virtual Address: {hex(section.VirtualAddress)}")
       print(f"Virtual Size: {hex(section.Misc_VirtualSize)}")
       print(f"Raw Size: {hex(section.SizeOfRawData)}")
   ```

### B. Code Analysis

1. **IDA Pro Analysis**
   ```python
   # Load file in IDA Pro
   # Analyze main function
   def analyze_main():
       main = ida_funcs.get_func(ida_name.get_name_ea(0, "main"))
       if main:
           print(f"Main function at {hex(main.start_ea)}")
           
           # Get cross references
           for xref in idautils.XrefsTo(main.start_ea):
               print(f"Called from {hex(xref.frm)}")
   ```

2. **Ghidra Analysis**
   ```java
   // Decompile function
   public void analyzeFunction() {
       Function function = getFunctionAt(toAddr(0x401000));
       DecompileResults results = decompiler.decompileFunction(
           function,
           0,
           TaskMonitor.DUMMY
       );
       println(results.getDecompiledFunction().getC());
   }
   ```

## Lab 2: Dynamic Analysis

### A. Process Monitoring

1. **Process Monitor**
   ```powershell
   # Start Process Monitor
   procmon.exe /BackingFile c:\analysis\procmon.pml
   
   # Filter events
   Process Name contains suspicious.exe
   Operation is CreateFile
   Operation is RegSetValue
   Operation is TCP Send
   Operation is TCP Receive
   ```

2. **API Monitoring**
   ```python
   from winappdbg import Debug, EventHandler
   
   class ApiMonitor(EventHandler):
       def create_process(self, event):
           process = event.get_process()
           print(f"Process created: {process.get_filename()}")
           
       def load_dll(self, event):
           module = event.get_module()
           print(f"DLL loaded: {module.get_filename()}")
           
       def create_file(self, event):
           filename = event.get_filename()
           print(f"File created: {filename}")
   
   debug = Debug(ApiMonitor())
   try:
       debug.loop()
   finally:
       debug.stop()
   ```

### B. Network Analysis

1. **Wireshark Capture**
   ```bash
   # Start capture
   tshark -i eth0 -w capture.pcap
   
   # Filter traffic
   tshark -r capture.pcap -Y "ip.addr == 192.168.56.10"
   
   # Extract HTTP
   tshark -r capture.pcap -Y "http" -T fields -e http.host -e http.request.uri
   ```

2. **Network Connections**
   ```powershell
   # Monitor connections
   netstat -anb | findstr suspicious.exe
   
   # Track DNS
   Get-DnsClientCache | Where-Object {$_.Data -match "malicious"}
   ```

## Lab 3: Memory Analysis

### A. Memory Acquisition

1. **Memory Dump**
   ```powershell
   # Create memory dump
   winpmem-2.1.exe memory.raw
   
   # Convert dump
   volatility -f memory.raw imageinfo
   ```

2. **Process Analysis**
   ```python
   import volatility3
   from volatility3.framework import contexts
   
   # Load memory dump
   context = contexts.Context()
   context.load_file("memory.raw")
   
   # List processes
   for proc in context.list_processes():
       print(f"PID: {proc.UniqueProcessId}")
       print(f"Name: {proc.ImageFileName}")
       print(f"Start: {proc.CreateTime}")
   ```

### B. Memory Forensics

1. **Volatility Analysis**
   ```bash
   # Process list
   vol.py -f memory.raw windows.pslist
   
   # Network connections
   vol.py -f memory.raw windows.netscan
   
   # Loaded DLLs
   vol.py -f memory.raw windows.dlllist
   ```

2. **String Extraction**
   ```python
   from volatility3.framework import interfaces
   
   def extract_strings(context, proc_id):
       proc_layer = context.layers[proc_id]
       for offset in range(0, proc_layer.maximum_address):
           try:
               data = proc_layer.read(offset, 100)
               if is_printable(data):
                   print(f"Found at {hex(offset)}: {data}")
           except:
               continue
   ```

## Lab 4: Reverse Engineering

### A. Debugging

1. **x64dbg Setup**
   ```
   # Load executable
   1. File > Open
   2. Set breakpoints
   3. Run > Start debugging
   
   # Analysis
   1. Step through code
   2. Examine registers
   3. Watch memory
   4. Track API calls
   ```

2. **WinDbg Analysis**
   ```
   # Commands
   !analyze -v    # Verbose analysis
   k              # Stack trace
   !process 0 0   # Process info
   !dlls          # Loaded DLLs
   
   # Breakpoints
   bp kernel32!CreateFileW
   bp kernel32!WriteFile
   bp ws2_32!send
   ```

### B. Code Analysis

1. **Assembly Analysis**
   ```nasm
   ; Example decryption routine
   decrypt_loop:
       mov al, byte [esi]    ; Load encrypted byte
       xor al, 0x35         ; XOR with key
       mov byte [edi], al   ; Store decrypted byte
       inc esi              ; Next source byte
       inc edi              ; Next destination byte
       dec ecx              ; Decrease counter
       jnz decrypt_loop     ; Continue if not zero
   ```

2. **Control Flow**
   ```python
   def analyze_control_flow(function_start):
       blocks = []
       current = function_start
       
       while current:
           block = BasicBlock(current)
           blocks.append(block)
           
           # Find branches
           if is_conditional_jump(current.last_instruction):
               true_branch = get_true_branch(current)
               false_branch = get_false_branch(current)
               blocks.extend([true_branch, false_branch])
           
           current = get_next_block(current)
       
       return blocks
   ```

## Evaluasi

### A. Kriteria Penilaian

1. **Technical Skills (40%)**
   - Tool usage
   - Analysis methods
   - Documentation
   - Problem solving

2. **Analysis Report (30%)**
   - Findings
   - Methodology
   - Evidence
   - Recommendations

3. **Presentation (30%)**
   - Technical depth
   - Clarity
   - Demo
   - Q&A

### B. Deliverables

1. **Analysis Report**
   - Executive summary
   - Technical details
   - IOCs
   - Mitigation steps

2. **Presentation**
   - 20 minutes
   - Live demo
   - Analysis walkthrough
   - Q&A session

## Referensi

1. Practical Malware Analysis
2. The Art of Memory Forensics
3. Reversing: Secrets of Reverse Engineering
4. Windows Internals

## Appendix

### A. Tool Commands

1. **Static Analysis**
   ```bash
   # PE Analysis
   pestudio suspicious.exe
   
   # String extraction
   strings -a -e l suspicious.exe
   
   # Resource analysis
   rescle -l suspicious.exe
   ```

2. **Dynamic Analysis**
   ```bash
   # Process monitoring
   procmon /BackingFile log.pml
   
   # Network capture
   tcpdump -i eth0 -w capture.pcap
   
   # Registry monitoring
   regshot
   ```

### B. Analysis Scripts

1. **PE Parser**
   ```python
   import pefile
   
   def analyze_pe(filename):
       pe = pefile.PE(filename)
       
       print("Sections:")
       for section in pe.sections:
           print(f"{section.Name.decode().rstrip('\x00')}:")
           print(f"  Virtual Address: {hex(section.VirtualAddress)}")
           print(f"  Virtual Size: {hex(section.Misc_VirtualSize)}")
           print(f"  Raw Size: {hex(section.SizeOfRawData)}")
       
       print("\nImports:")
       for entry in pe.DIRECTORY_ENTRY_IMPORT:
           print(f"{entry.dll.decode()}:")
           for imp in entry.imports:
               print(f"  {imp.name.decode() if imp.name else hex(imp.ordinal)}")
   ```

2. **API Monitor**
   ```python
   import winappdbg
   
   class ApiMonitor(winappdbg.EventHandler):
       def create_process(self, event):
           process = event.get_process()
           print(f"Process created: {process.get_filename()}")
       
       def load_dll(self, event):
           module = event.get_module()
           print(f"DLL loaded: {module.get_filename()}")
       
       def create_file(self, event):
           filename = event.get_filename()
           print(f"File created: {filename}")
   
   debug = winappdbg.Debug(ApiMonitor())
   try:
       debug.loop()
   finally:
       debug.stop()
   ```

### C. Analysis Checklists

1. **Static Analysis**
   - [ ] File properties
   - [ ] Hash values
   - [ ] Strings analysis
   - [ ] PE analysis
   - [ ] Import analysis
   - [ ] Resource analysis
   - [ ] Code analysis
   - [ ] Anti-analysis checks

2. **Dynamic Analysis**
   - [ ] Process monitoring
   - [ ] File operations
   - [ ] Registry changes
   - [ ] Network activity
   - [ ] Memory analysis
   - [ ] API calls
   - [ ] System changes
   - [ ] Behavioral patterns
