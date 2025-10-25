#!/usr/bin/env python3
"""
Router Credential Testing Tool
Authorized use only for security assessments
"""

import requests
import argparse
from typing import List, Dict

class RouterSecurityTester:
    def __init__(self, target: str, timeout: int = 10):
        self.target = target
        self.timeout = timeout
        self.session = requests.Session()
        self.results = []
        
    def test_credentials(self, credentials_list: List[Dict]) -> List[str]:
        print(f"[*] Testing {len(credentials_list)} credential combinations...")
        
        for creds in credentials_list:
            username = creds['username']
            password = creds['password']
            
            if self.attempt_login(username, password):
                result = f"VALID: {username}:{password}"
                self.results.append(('SUCCESS', result))
                print(f"[+] {result}")
                break
            else:
                result = f"INVALID: {username}"
                self.results.append(('FAILED', result))
                print(f"[-] {result}")
                
        return self.results
    
    def attempt_login(self, username: str, password: str) -> bool:
        try:
            login_data = {
                'username': username,
                'password': password
            }
            
            response = self.session.post(
                f"http://{self.target}/check.jst",
                data=login_data,
                allow_redirects=False,
                timeout=self.timeout
            )
            
            if response.status_code == 302:
                return True
            elif 'incorrect' not in response.text.lower():
                return True
                
        except requests.RequestException as e:
            print(f"[!] Request failed: {e}")
            
        return False

def main():
    parser = argparse.ArgumentParser(description='Router Credential Testing Tool')
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    
    args = parser.parse_args()
    
    test_credentials = [
        {'username': 'admin', 'password': 'admin'},
        {'username': 'admin', 'password': 'password'},
        {'username': 'cusadmin', 'password': 'high5'},
        {'username': 'user', 'password': 'user'},
    ]
    
    print("🔒 Router Security Assessment Tool")
    print("⚠️  Authorized use only!")
    print(f"🎯 Target: {args.target}")
    print("-" * 50)
    
    tester = RouterSecurityTester(args.target, args.timeout)
    results = tester.test_credentials(test_credentials)
    
    print("-" * 50)
    print("📊 Assessment Complete:")
    for status, result in results:
        if status == 'SUCCESS':
            print(f"🚨 {result}")

if __name__ == "__main__":
    main()
