#!/usr/bin/env python3
"""
Parse SNMP extend OIDs and decode extend names.
Converts hex-encoded OID suffixes to readable extend names and shows what they do.
"""

import sys
import re
import subprocess
from collections import defaultdict

def decode_oid_suffix(hex_string):
    """
    Convert OID suffix like '5.82.69.83.69.84' to readable name.
    First number is length, rest are ASCII values.
    """
    parts = hex_string.split('.')
    if not parts:
        return None
    
    try:
        length = int(parts[0])
        if len(parts) - 1 < length:
            return None
        
        name = ''.join(chr(int(parts[i])) for i in range(1, length + 1))
        return name
    except (ValueError, IndexError):
        return None

def parse_snmpwalk_output(output):
    """
    Parse snmpwalk output and extract extend information.
    Groups by extend name and extracts key details.
    """
    extends = defaultdict(dict)
    
    for line in output.split('\n'):
        if not line.strip():
            continue
        
        # Match OID lines
        match = re.match(r'iso\.3\.6\.1\.4\.1\.8072\.1\.3\.2\.2\.1\.(\d+)\.(.+?)\s*=\s*(.+)', line)
        if match:
            oid_type = int(match.group(1))
            oid_suffix = match.group(2)
            value = match.group(3).strip('"')
            
            extend_name = decode_oid_suffix(oid_suffix)
            if not extend_name:
                continue
            
            # Map OID types to readable names
            oid_map = {
                2: 'command',
                3: 'args',
                4: 'input',
                5: 'cache_time',
                6: 'exec_type',
                7: 'run_type',
                20: 'storage',
                21: 'status',
            }
            
            if oid_type in oid_map:
                extends[extend_name][oid_map[oid_type]] = value
        
        # Parse output lines
        match = re.match(r'iso\.3\.6\.1\.4\.1\.8072\.1\.3\.2\.3\.1\.\d+\.(.+?)\s*=\s*(.+)', line)
        if match:
            oid_suffix = match.group(1)
            output_value = match.group(2).strip('"')
            
            extend_name = decode_oid_suffix(oid_suffix)
            if extend_name and 'output' not in extends[extend_name]:
                extends[extend_name]['output'] = output_value
        
        # Parse result code
        match = re.match(r'iso\.3\.6\.1\.4\.1\.8072\.1\.3\.2\.4\.1\.4\.(.+?)\s*=\s*INTEGER:\s*(\d+)', line)
        if match:
            oid_suffix = match.group(1)
            result = int(match.group(2))
            
            extend_name = decode_oid_suffix(oid_suffix)
            if extend_name:
                extends[extend_name]['result'] = result
    
    return extends

def pretty_print_extends(extends):
    """Pretty print discovered extends."""
    if not extends:
        print("[!] No extends found")
        return
    
    print(f"\n[+] Found {len(extends)} SNMP extend(s):\n")
    
    for name, data in sorted(extends.items()):
        print(f"═" * 60)
        print(f"Name: {name}")
        print(f"─" * 60)
        
        if 'command' in data:
            print(f"Command: {data['command']}")
        if 'args' in data and data['args']:
            print(f"Args: {data['args']}")
        if 'run_type' in data:
            run_types = {
                '1': 'run-on-read',
                '2': 'run-on-set',
                '3': 'run-periodically'
            }
            print(f"Run Type: {run_types.get(data['run_type'], data['run_type'])}")
        if 'exec_type' in data:
            exec_types = {
                '1': 'exec',
                '2': 'shell'
            }
            print(f"Exec Type: {exec_types.get(data['exec_type'], data['exec_type'])}")
        if 'output' in data:
            print(f"Output: {data['output']}")
        if 'result' in data:
            result_msg = "Success" if data['result'] == 0 else f"Failed (code {data['result']})"
            print(f"Result: {result_msg}")
        
        print()

def run_snmpwalk(target, community="public", version="2c"):
    """Execute snmpwalk command and return output."""
    try:
        cmd = ['snmpwalk', f'-v{version}', '-c', community, target, '1.3.6.1.4.1.8072.1.3.2']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            print(f"[!] snmpwalk failed: {result.stderr}")
            return None
        
        return result.stdout
    except FileNotFoundError:
        print("[!] snmpwalk not found. Install with: apt-get install snmp")
        return None
    except subprocess.TimeoutExpired:
        print("[!] snmpwalk timeout")
        return None
    except Exception as e:
        print(f"[!] Error running snmpwalk: {e}")
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 snmp_extend_parser.py <target_ip> [community] [version]")
        print("       python3 snmp_extend_parser.py <target_ip> public 2c")
        print("\nOr pipe snmpwalk output:")
        print("       snmpwalk -v2c -c public <target> 1.3.6.1.4.1.8072.1.3.2 | python3 snmp_extend_parser.py")
        sys.exit(1)
    
    target = sys.argv[1]
    community = sys.argv[2] if len(sys.argv) > 2 else "public"
    version = sys.argv[3] if len(sys.argv) > 3 else "2c"
    
    print(f"[*] Querying SNMP extends on {target}...")
    output = run_snmpwalk(target, community, version)
    
    if not output:
        sys.exit(1)
    
    print(f"[+] Received {len(output)} bytes of SNMP data")
    
    extends = parse_snmpwalk_output(output)
    pretty_print_extends(extends)
    
    # Print execution commands
    if extends:
        print(f"\n{'═' * 60}")
        print("Execute extends with:")
        print(f"{'─' * 60}")
        for name in sorted(extends.keys()):
            oid = '1.3.6.1.4.1.8072.1.3.2.3.1.1.' + '.'.join(str(ord(c)) for c in name)
            print(f"snmpget -v2c -c {community} {target} {oid}")
        print()

if __name__ == '__main__':
    main()
