#!/usr/bin/env python3
"""
Network Security Scanner
Authorized security assessment tool
"""

import subprocess
import argparse

class NetworkScanner:
    def __init__(self, target: str):
        self.target = target
        self.results = {}
    
    def run_nmap_scan(self, ports: str = "1-1000") -> dict:
        print(f"[*] Scanning {self.target} on ports {ports}...")
        
        try:
            command = [
                'nmap', '-sS', '-T4', 
                '-p', ports,
                '--open',
                '-oG', '-',
                self.target
            ]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            self.results['nmap'] = result.stdout
            return {'success': True, 'output': result.stdout}
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Scan timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def analyze_results(self) -> dict:
        analysis = {
            'open_ports': [],
            'potential_risks': []
        }
        
        if 'nmap' in self.results:
            lines = self.results['nmap'].split('\n')
            for line in lines:
                if '/open/' in line:
                    parts = line.split()
                    port_info = parts[4] if len(parts) > 4 else 'Unknown'
                    analysis['open_ports'].append(port_info)
                    
                    if 'http' in port_info.lower():
                        analysis['potential_risks'].append('HTTP service detected')
                    if 'telnet' in port_info.lower():
                        analysis['potential_risks'].append('Telnet service detected')
        
        return analysis

def main():
    parser = argparse.ArgumentParser(description='Network Security Scanner')
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--ports', default='1-1000', help='Port range to scan')
    
    args = parser.parse_args()
    
    print("🌐 Network Security Scanner")
    print("⚠️  Authorized use only!")
    print(f"🎯 Target: {args.target}")
    print("-" * 50)
    
    scanner = NetworkScanner(args.target)
    scan_result = scanner.run_nmap_scan(args.ports)
    
    if scan_result['success']:
        analysis = scanner.analyze_results()
        print("📊 Scan Results:")
        print(f"Open Ports: {analysis['open_ports']}")
        if analysis['potential_risks']:
            print("🚨 Potential Risks:")
            for risk in analysis['potential_risks']:
                print(f"  - {risk}")
    else:
        print(f"❌ Scan failed: {scan_result['error']}")

if __name__ == "__main__":
    main()
