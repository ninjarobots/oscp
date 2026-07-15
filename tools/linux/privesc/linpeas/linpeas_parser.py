#!/usr/bin/env python3
"""
LinPEAS output parser for OSCP labs.
Extracts actionable privilege escalation vectors from verbose LinPEAS output.
Usage: python3 linpeas_parser.py linpeas_output.txt
"""

import sys
import re
from collections import defaultdict

class LinPEASParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.findings = defaultdict(list)
        self.parse()

    def parse(self):
        with open(self.filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        self.extract_suid()
        self.extract_sudo()
        self.extract_cron()
        self.extract_writable()
        self.extract_kernel()
        self.extract_capabilities()
        self.extract_passwords()
        self.extract_cves()

    def extract_suid(self):
        """Extract SUID binaries"""
        pattern = r'SUID files.*?(?=\[|$)'
        matches = re.findall(pattern, open(self.filepath).read(), re.DOTALL | re.IGNORECASE)
        if matches:
            # Parse SUID output
            suid_section = matches[0] if matches else ""
            for line in suid_section.split('\n'):
                if line.strip() and '/bin' in line or '/usr' in line or '/sbin' in line:
                    self.findings['SUID Binaries'].append(line.strip())

    def extract_sudo(self):
        """Extract sudo privileges"""
        with open(self.filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        # Look for sudo -l output
        patterns = [
            r'(\(ALL\).*?NOPASSWD.*)',
            r'(User.*?may.*?run.*?)',
            r'(ALL=\(.*?\).*?)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match and 'NOPASSWD' in match:
                    self.findings['Sudo - NOPASSWD'].append(match.strip())
                elif match:
                    self.findings['Sudo - Other'].append(match.strip())

    def extract_cron(self):
        """Extract cron jobs"""
        with open(self.filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        # Look for cron sections
        pattern = r'cron.*?(?=\[|$)'
        matches = re.findall(pattern, content, re.DOTALL | re.IGNORECASE)
        if matches:
            for match in matches:
                for line in match.split('\n'):
                    if line.strip() and ('root' in line.lower() or '.sh' in line or '.py' in line):
                        self.findings['Cron Jobs'].append(line.strip())

    def extract_writable(self):
        """Extract writable directories and files"""
        with open(self.filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        patterns = [
            r'(\/tmp.*writable)',
            r'(\/var\/tmp.*writable)',
            r'(\/dev\/shm.*writable)',
            r'(\/home.*writable)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                self.findings['Writable Directories'].append(match.strip())

    def extract_kernel(self):
        """Extract kernel version and potential exploits"""
        with open(self.filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        # Look for kernel version
        kernel_pattern = r'Linux.*?(\d+\.\d+\.\d+)'
        kernel_matches = re.findall(kernel_pattern, content)
        if kernel_matches:
            self.findings['Kernel Version'].extend(kernel_matches)
        
        # Look for CVEs
        cve_pattern = r'CVE-\d{4}-\d{4,5}'
        cve_matches = re.findall(cve_pattern, content)
        if cve_matches:
            self.findings['Kernel CVEs'].extend(set(cve_matches))

    def extract_capabilities(self):
        """Extract file capabilities"""
        with open(self.filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        pattern = r'(.*cap_.*?(?:\s|$))'
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            if match.strip():
                self.findings['Capabilities'].append(match.strip())

    def extract_passwords(self):
        """Look for exposed passwords or credentials"""
        with open(self.filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        patterns = [
            r'password.*?[:=]\s*([^\s\n]+)',
            r'(passwd|password)\s*=\s*([^\s\n]+)',
            r'api[_-]?key.*?[:=]\s*([^\s\n]+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    self.findings['Credentials'].extend(match)
                else:
                    self.findings['Credentials'].append(match)

    def extract_cves(self):
        """Extract CVEs mentioned in output"""
        with open(self.filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        pattern = r'CVE-\d{4}-\d{4,5}'
        cves = re.findall(pattern, content)
        for cve in set(cves):
            self.findings['Potential CVE Exploits'].append(cve)

    def print_report(self):
        """Print formatted report"""
        print("\n" + "="*80)
        print("LINPEAS PRIVILEGE ESCALATION FINDINGS")
        print("="*80 + "\n")
        
        # Priority order
        priority = [
            'Sudo - NOPASSWD',
            'Potential CVE Exploits',
            'SUID Binaries',
            'Capabilities',
            'Cron Jobs',
            'Writable Directories',
            'Credentials',
            'Kernel CVEs',
            'Kernel Version',
            'Sudo - Other',
        ]
        
        for category in priority:
            if category in self.findings and self.findings[category]:
                print(f"\n{'['} {category} {']'}")
                print("-" * 80)
                for finding in self.findings[category][:10]:  # Limit to 10 per category
                    print(f"  • {finding}")
                if len(self.findings[category]) > 10:
                    print(f"  ... and {len(self.findings[category]) - 10} more")

    def export_json(self, output_file):
        """Export findings as JSON for further analysis"""
        import json
        with open(output_file, 'w') as f:
            json.dump(dict(self.findings), f, indent=2)
        print(f"\n[+] Findings exported to {output_file}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 linpeas_parser.py <linpeas_output.txt> [--json output.json]")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    try:
        parser = LinPEASParser(filepath)
        parser.print_report()
        
        if '--json' in sys.argv:
            json_idx = sys.argv.index('--json')
            if json_idx + 1 < len(sys.argv):
                parser.export_json(sys.argv[json_idx + 1])
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error parsing file: {e}")
        sys.exit(1)
