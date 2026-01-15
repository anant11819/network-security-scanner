# 🔍 Network Security Scanner - Intermediate Tool

**Advanced network security scanner with multi-threaded port scanning, service detection, and vulnerability assessment.**

Built with Python for penetration testing and network security auditing.

---

## 🎯 Features

✅ **Multi-threaded Port Scanning** - Fast concurrent scanning (configurable threads)
✅ **Service Detection** - Identifies 18+ common services
✅ **Banner Grabbing** - Retrieves service version information  
✅ **Vulnerability Assessment** - Checks for known vulnerable services
✅ **Color-coded Output** - Easy-to-read terminal output
✅ **JSON Export** - Save scan results for analysis
✅ **CLI Arguments** - Flexible command-line interface
✅ **Security Recommendations** - Actionable security advice

---

## 🛠️ Tech Stack

- **Python 3.6+**
- **Libraries:**
  - `socket` - TCP connection handling
  - `threading` - Multi-threaded scanning
  - `argparse` - CLI argument parsing
  - `colorama` - Terminal colors
  - `json` - Result export

---

## 🚀 Installation

```bash
# Clone repository
git clone https://github.com/anant11819/network-security-scanner.git
cd network-security-scanner

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage

### Basic Scan
```bash
python network_scanner.py 192.168.1.1
```

### Custom Port Range
```bash
python network_scanner.py 192.168.1.1 -s 1 -e 65535
```

### Fast Scan (More Threads)
```bash
python network_scanner.py example.com -th 200
```

### Export Results
```bash
python network_scanner.py 192.168.1.1 -o scan_report.json
```

### Full Options
```bash
python network_scanner.py TARGET [OPTIONS]

Positional Arguments:
  target              Target IP address or hostname

Optional Arguments:
  -s, --start         Start port (default: 1)
  -e, --end           End port (default: 1024)
  -t, --timeout       Timeout in seconds (default: 1)
  -th, --threads      Number of threads (default: 100)
  -o, --output        Output JSON file
```

---

## 📊 Output Example

```
======================================================================
🔐 NETWORK SECURITY SCANNER - Intermediate Tool
======================================================================
Port Scanning | Service Detection | Vulnerability Assessment
======================================================================

Resolving target: example.com...
✅ Resolved to: 93.184.216.34

======================================================================
🔍 PORT SCANNING - 93.184.216.34
======================================================================

Scanning ports 1-1024...

[+] Port 80 is OPEN - HTTP
[+] Port 443 is OPEN - HTTPS

Scan completed in 12.45 seconds
Found 2 open ports

======================================================================
📄 DETAILED SCAN REPORT
======================================================================

Target: example.com
Scan Time: 2026-01-15 22:00:00
Total Ports Scanned: 1024
Open Ports Found: 2

Open Ports Details:

  Port    80 | HTTP            | OPEN
  Port   443 | HTTPS           | OPEN

======================================================================
⚠️  VULNERABILITY ASSESSMENT
======================================================================

✅ No critical vulnerabilities detected in common ports

======================================================================
🛡️  SECURITY RECOMMENDATIONS
======================================================================

General Recommendations:
  • Close unnecessary open ports
  • Use firewall rules to restrict access
  • Keep all services updated
  • Disable unused services
  • Use strong authentication
  • Implement network segmentation
  • Enable logging and monitoring

✅ Results exported to scan_report.json
```

---

## 🔥 Advanced Features

### 1. Vulnerability Detection
Automatically identifies vulnerable services:
- **FTP (21)** - Unencrypted credentials
- **Telnet (23)** - No encryption
- **SMB (445)** - EternalBlue vulnerability
- **RDP (3389)** - Brute force/BlueKeep
- **Redis (6379)** - Authentication bypass

### 2. Banner Grabbing
Retrieves service banners for version detection

### 3. Multi-threading
Configurable thread pool for faster scanning

### 4. JSON Export
Structured output for integration with other tools

---

## ⚠️ Legal Disclaimer

**IMPORTANT:** This tool is for educational and authorized security testing ONLY.

- Only scan networks you own or have written permission to test
- Unauthorized port scanning may be illegal in your jurisdiction
- Use responsibly and ethically
- Author is not responsible for misuse

---

## 📚 Learning Objectives

This intermediate project teaches:
- Socket programming in Python
- Multi-threading and concurrency
- CLI application development
- Security vulnerability assessment
- Network protocols and services
- Exception handling
- File I/O and JSON processing

---

## 🔧 Future Enhancements

- [ ] OS detection via TTL analysis
- [ ] Integration with CVE database API
- [ ] Stealth scanning techniques
- [ ] UDP port scanning
- [ ] GUI interface with Tkinter
- [ ] Nmap XML output compatibility
- [ ] CIDR range scanning
- [ ] Service fingerprinting

---

## 📄 License

MIT License - Open source and free to use

---

## 👤 Author

**Anant**
- GitHub: [@anant11819](https://github.com/anant11819)
- Portfolio: [anant11819.github.io/portfolio-website](https://anant11819.github.io/portfolio-website/)

---

⭐ **If this tool helps you learn cybersecurity, please star the repository!** ⭐

Stay ethical! 🔐
