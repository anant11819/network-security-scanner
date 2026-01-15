#!/usr/bin/env python3
"""
Network Security Scanner - Intermediate Cybersecurity Tool
Advanced port scanning, service detection, and vulnerability assessment
Requires: python-nmap, requests, colorama
"""

import socket
import sys
import threading
import time
from datetime import datetime
import json
import argparse

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    # Fallback if colorama not installed
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = ''
    class Style:
        BRIGHT = RESET_ALL = ''

# Common ports and their services
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
}

# Known vulnerable ports
VULNERABLE_PORTS = {
    21: 'FTP - Often unencrypted, credentials exposed',
    23: 'Telnet - Unencrypted protocol, high risk',
    445: 'SMB - Vulnerable to EternalBlue (MS17-010)',
    3389: 'RDP - Brute force attacks, BlueKeep vulnerability',
    6379: 'Redis - Often exposed without authentication'
}

class NetworkScanner:
    def __init__(self, target, start_port=1, end_port=1024, timeout=1, threads=100):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.lock = threading.Lock()
        self.scan_results = {}
        
    def resolve_target(self):
        """
        Resolve hostname to IP address
        """
        try:
            ip_address = socket.gethostbyname(self.target)
            return ip_address
        except socket.gaierror:
            return None

    def scan_port(self, port):
        """
        Scan a single port
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                    service = self.detect_service(port)
                    banner = self.grab_banner(port)
                    self.scan_results[port] = {
                        'service': service,
                        'banner': banner,
                        'state': 'open'
                    }
                    print(f"{Fore.GREEN}[+] Port {port} is OPEN - {service}{Style.RESET_ALL}")
        except:
            pass

    def detect_service(self, port):
        """
        Detect service running on port
        """
        return COMMON_PORTS.get(port, 'Unknown')

    def grab_banner(self, port):
        """
        Try to grab banner from the service
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            
            # Try to receive banner
            sock.send(b'\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else 'No banner'
        except:
            return 'Banner grab failed'

    def port_scan_threaded(self):
        """
        Multi-threaded port scanner
        """
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}🔍 PORT SCANNING - {self.target}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        print(f"Scanning ports {self.start_port}-{self.end_port}...\n")
        
        start_time = time.time()
        
        # Create thread pool
        threads = []
        port_range = range(self.start_port, self.end_port + 1)
        
        for port in port_range:
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= self.threads:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for t in threads:
            t.join()
        
        end_time = time.time()
        scan_duration = round(end_time - start_time, 2)
        
        print(f"\n{Fore.YELLOW}Scan completed in {scan_duration} seconds{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Found {len(self.open_ports)} open ports{Style.RESET_ALL}\n")

    def vulnerability_assessment(self):
        """
        Assess vulnerabilities based on open ports
        """
        print(f"{Fore.RED}{'='*70}")
        print(f"{Fore.RED}⚠️  VULNERABILITY ASSESSMENT")
        print(f"{Fore.RED}{'='*70}{Style.RESET_ALL}\n")
        
        vulnerabilities = []
        
        for port in self.open_ports:
            if port in VULNERABLE_PORTS:
                vuln_info = {
                    'port': port,
                    'service': COMMON_PORTS.get(port, 'Unknown'),
                    'risk': 'HIGH',
                    'description': VULNERABLE_PORTS[port]
                }
                vulnerabilities.append(vuln_info)
                
                print(f"{Fore.RED}[!] HIGH RISK - Port {port} ({vuln_info['service']})")
                print(f"    {vuln_info['description']}{Style.RESET_ALL}\n")
        
        if not vulnerabilities:
            print(f"{Fore.GREEN}✅ No critical vulnerabilities detected in common ports{Style.RESET_ALL}\n")
        
        return vulnerabilities

    def generate_report(self):
        """
        Generate comprehensive scan report
        """
        print(f"{Fore.MAGENTA}{'='*70}")
        print(f"{Fore.MAGENTA}📄 DETAILED SCAN REPORT")
        print(f"{Fore.MAGENTA}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"Target: {self.target}")
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Ports Scanned: {self.end_port - self.start_port + 1}")
        print(f"Open Ports Found: {len(self.open_ports)}\n")
        
        if self.open_ports:
            print(f"{Fore.CYAN}Open Ports Details:{Style.RESET_ALL}\n")
            for port in sorted(self.open_ports):
                info = self.scan_results[port]
                print(f"  Port {port:5d} | {info['service']:15s} | {info['state'].upper()}")
                if info['banner'] != 'No banner' and info['banner'] != 'Banner grab failed':
                    print(f"           Banner: {info['banner'][:50]}...")
                print()

    def security_recommendations(self):
        """
        Provide security recommendations
        """
        print(f"{Fore.BLUE}{'='*70}")
        print(f"{Fore.BLUE}🛡️  SECURITY RECOMMENDATIONS")
        print(f"{Fore.BLUE}{'='*70}{Style.RESET_ALL}\n")
        
        print("General Recommendations:")
        print("  • Close unnecessary open ports")
        print("  • Use firewall rules to restrict access")
        print("  • Keep all services updated")
        print("  • Disable unused services")
        print("  • Use strong authentication")
        print("  • Implement network segmentation")
        print("  • Enable logging and monitoring\n")
        
        if 21 in self.open_ports or 23 in self.open_ports:
            print(f"{Fore.RED}Critical: Replace FTP/Telnet with SFTP/SSH{Style.RESET_ALL}")
        if 3389 in self.open_ports:
            print(f"{Fore.RED}Critical: Secure RDP with VPN or disable if not needed{Style.RESET_ALL}")
        if 445 in self.open_ports:
            print(f"{Fore.RED}Critical: Apply SMB security patches (MS17-010){Style.RESET_ALL}")
        
        print()

    def export_json(self, filename='scan_results.json'):
        """
        Export results to JSON
        """
        report_data = {
            'target': self.target,
            'scan_time': datetime.now().isoformat(),
            'total_ports_scanned': self.end_port - self.start_port + 1,
            'open_ports': len(self.open_ports),
            'results': self.scan_results
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2)
            print(f"{Fore.GREEN}✅ Results exported to {filename}{Style.RESET_ALL}\n")
        except Exception as e:
            print(f"{Fore.RED}❌ Failed to export: {str(e)}{Style.RESET_ALL}\n")

def print_banner():
    """
    Print tool banner
    """
    banner = f"""
{Fore.CYAN}{'='*70}
{Fore.CYAN}🔐 NETWORK SECURITY SCANNER - Intermediate Tool
{Fore.CYAN}{'='*70}
{Fore.YELLOW}Port Scanning | Service Detection | Vulnerability Assessment
{Fore.CYAN}{'='*70}{Style.RESET_ALL}
    """
    print(banner)

def main():
    print_banner()
    
    # Argument parser
    parser = argparse.ArgumentParser(description='Network Security Scanner')
    parser.add_argument('target', help='Target IP or hostname')
    parser.add_argument('-s', '--start', type=int, default=1, help='Start port (default: 1)')
    parser.add_argument('-e', '--end', type=int, default=1024, help='End port (default: 1024)')
    parser.add_argument('-t', '--timeout', type=float, default=1, help='Timeout in seconds (default: 1)')
    parser.add_argument('-th', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('-o', '--output', help='Output JSON file')
    
    args = parser.parse_args()
    
    # Create scanner instance
    scanner = NetworkScanner(
        target=args.target,
        start_port=args.start,
        end_port=args.end,
        timeout=args.timeout,
        threads=args.threads
    )
    
    # Resolve target
    print(f"Resolving target: {args.target}...")
    ip = scanner.resolve_target()
    
    if not ip:
        print(f"{Fore.RED}❌ Error: Unable to resolve hostname{Style.RESET_ALL}")
        sys.exit(1)
    
    print(f"{Fore.GREEN}✅ Resolved to: {ip}{Style.RESET_ALL}")
    
    # Perform scan
    try:
        scanner.port_scan_threaded()
        scanner.generate_report()
        scanner.vulnerability_assessment()
        scanner.security_recommendations()
        
        # Export if requested
        if args.output:
            scanner.export_json(args.output)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main()
