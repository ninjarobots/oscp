#!/usr/bin/env python3
"""
WinPEAS Output Parser - OSCP Lab Tool
Parses WinPEAS JSON output and extracts critical findings
"""

import json
import sys
from collections import defaultdict

def parse_winpeas(json_file):
    """Parse WinPEAS JSON output"""
    
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    findings = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }
    
    # Extract by severity
    for item in data.get('ProgramData', []):
        if item.get('severity') == 'Critical':
            findings['critical'].append(item)
        elif item.get('severity') == 'High':
            findings['high'].append(item)
        elif item.get('severity') == 'Medium':
            findings['medium'].append(item)
        elif item.get('severity') == 'Low':
            findings['low'].append(item)
        else:
            findings['info'].append(item)
    
    return findings

def print_findings(findings):
    """Print organized findings"""
    
    print("\n" + "="*80)
    print("WINPEAS FINDINGS SUMMARY")
    print("="*80)
    
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        items = findings[severity]
        if items:
            print(f"\n[{severity.upper()}] - {len(items)} findings")
            for item in items:
                print(f"  - {item.get('title', 'Unknown')}")
                if item.get('description'):
                    print(f"    Description: {item['description']}")
                if item.get('remediation'):
                    print(f"    Fix: {item['remediation']}")

def extract_privesc_vectors(findings):
    """Extract privilege escalation opportunities"""
    
    print("\n" + "="*80)
    print("PRIVILEGE ESCALATION VECTORS")
    print("="*80)
    
    privesc = []
    
    # Look for unquoted service paths
    for item in findings['critical'] + findings['high']:
        if 'unquoted' in item.get('title', '').lower():
            privesc.append(f"Unquoted Service Path: {item.get('description')}")
        if 'suid' in item.get('title', '').lower():
            privesc.append(f"SUID Binary: {item.get('description')}")
        if 'sudo' in item.get('title', '').lower():
            privesc.append(f"Sudo Access: {item.get('description')}")
    
    if privesc:
        for vec in privesc:
            print(f"  [+] {vec}")
    else:
        print("  [*] No obvious privesc vectors found")

def extract_credentials(findings):
    """Extract potential credentials"""
    
    print("\n" + "="*80)
    print("POTENTIAL CREDENTIALS")
    print("="*80)
    
    creds = []
    
    for item in findings['critical'] + findings['high']:
        if any(x in item.get('title', '').lower() for x in ['password', 'cred', 'key', 'secret', 'token']):
            creds.append(item.get('description', 'Unknown'))
    
    if creds:
        for cred in creds:
            print(f"  [+] {cred}")
    else:
        print("  [*] No credentials found")

def extract_services(findings):
    """Extract running services with issues"""
    
    print("\n" + "="*80)
    print("VULNERABLE SERVICES")
    print("="*80)
    
    services = []
    
    for item in findings['critical'] + findings['high']:
        if 'service' in item.get('title', '').lower():
            services.append(item.get('description', 'Unknown'))
    
    if services:
        for service in services:
            print(f"  [+] {service}")
    else:
        print("  [*] No vulnerable services identified")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 winpeas_parser.py <winpeas_output.json>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    
    try:
        findings = parse_winpeas(json_file)
        print_findings(findings)
        extract_privesc_vectors(findings)
        extract_credentials(findings)
        extract_services(findings)
        
        print("\n" + "="*80)
        print("SUMMARY")
        print("="*80)
        print(f"Critical: {len(findings['critical'])}")
        print(f"High: {len(findings['high'])}")
        print(f"Medium: {len(findings['medium'])}")
        print(f"Low: {len(findings['low'])}")
        print(f"Info: {len(findings['info'])}")
        
    except Exception as e:
        print(f"Error parsing file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
