# 🧠 Elaina Inspector Pro

**Elaina Inspector Pro** is a next-generation GUI toolkit for **reverse engineering**, **malware analysis**, **network forensics**, **hardware & firmware analysis**, and **automated exploit research** — developed by the elite cybersecurity group **Elaina Core**.

The tool brings together static and dynamic binary analysis, packet capture and replay, crypto decoding, proxy interception, behavior detection, forensic recovery, and embedded firmware exploitation — all in one unified platform.

---

## 🧬 Key Features

### 🔧 Reverse Engineering
- Disassemble x86/x64/ARM binaries using Capstone engine
- Hex viewer and patcher (modify opcode, insert NOPs)
- ASCII/Unicode string extraction
- PE/ELF header parser
- Decompiler integration (RetDec or external)
- Shellcode analyzer and translator
- Function scanner with basic symbolic flow

### 🦠 Malware Analysis
- Static malware profiling (headers, imports, entropy, strings)
- Dynamic analysis with API hooking and syscall trace
- Signature detection (Elaina Core DB)
- Auto behavior classification: downloader, injector, RAT, etc.
- Shellcode format decoder (raw, Base64, poly)
- Auto unpacker and emulator support (planned)

### 🌐 Packet Analysis
- Live packet capture via `libpcap`
- Protocol parser for TCP, UDP, HTTP, DNS, TLS, custom
- Import `.pcap` files and analyze packet flows
- Replay TCP/UDP packets to simulate attacks
- Automated payload extraction from session
- Exploit detection and redirect to RE tab

### 🔓 Proxy Interceptor
- Built-in HTTP/HTTPS proxy with request logger
- Integration with Burp Suite & OWASP ZAP logs
- Auto-analyze requests for vulnerabilities:
  - SQLi, XSS, RCE, LFI, SSTI, IDOR, CSRF
- Convert HTTP requests to fuzzers or exploits

### 📦 Firmware Analysis
- Unpack embedded firmware images (binwalk-style)
- Analyze file systems (SquashFS, JFFS2, CramFS)
- Detect backdoors, hardcoded credentials, debug ports
- Emulate startup binary with QEMU (planned)
- Extract ELF from raw dumps and send to RE tab
- Identify IoT exploits and CVE-matching strings

### 🧠 Behavior Monitor
- Hook WinAPI / libc functions for live behavior tracing
- Syscall logging per process/thread
- Behavior scoring system (self-modifying, injection, beaconing)
- Real-time indicators of compromise (IOCs)
- Timeline view of execution flow
- Auto label file as malicious/suspicious/benign

### 🔐 Cryptographic Analysis
- Detect and decode XOR, Base64, AES, RC4, DES
- Brute-force XOR keys or weak passwords
- Auto crypto detection engine (static pattern-based)
- Decrypt encoded payloads and embedded keys
- Integration with hash cracking (Planned: hashcat bridge)

### 🔍 Forensics & Log Analysis
- Recover deleted files from disk images
- Parse log files: Windows EVTX, Linux syslog, Apache logs
- Extract timeline of user/system activities
- Disk sector viewer and hex-level editor
- Registry dump viewer and analysis
- Supports NTFS, EXT4, FAT32 parsing

### 🤖 AI & Automation
- Auto classify unknown binaries and payloads
- Suggest shellcode behavior (e.g., connect-back, download-exec)
- Auto-decrypt encoded payloads
- Behavior anomaly detection using heuristic + AI model
- ElainaScript AI plugin engine (planned)
- One-click full RE of unknown binaries

---

## 🚀 Quick Start

### Requirements
- OS: Linux (Debian, Ubuntu, Arch), or WSL2
- GTK3 development libraries
- GCC or Clang
- Capstone library
- libpcap
- (Optional): binwalk, qemu, retdec, burpsuite/zap

### Build Instructions

```bash
sudo apt install build-essential libgtk-3-dev libpcap-dev libcapstone-dev git
git clone https://github.com/ElainaCore/elaina_inspector_pro.git
cd elaina_inspector_pro
make
./elaina_inspector_pro
