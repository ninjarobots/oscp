#!/usr/bin/env python3
"""
Parse SNMP extend OIDs and decode extend names.
Converts hex-encoded OID suffixes to readable extend names and shows what they do.
"""

import sys
import re
import subprocess
import argparse
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


def name_to_oid_suffix(name):
    """
    Convert an extend name to its OID suffix.
    Format: <length>.<ascii_byte>.<ascii_byte>...
    e.g. 'RESET' -> '5.82.69.83.69.84'
    """
    return str(len(name)) + '.' + '.'.join(str(ord(c)) for c in name)


def parse_snmpwalk_output(output):
    """
    Parse snmpwalk output and extract extend information.
    Groups by extend name and extracts key details.
    """
    extends = defaultdict(dict)

    for line in output.split('\n'):
        if not line.strip():
            continue

        # Configuration OIDs (2.2.1.*)
        match = re.match(
            r'iso\.3\.6\.1\.4\.1\.8072\.1\.3\.2\.2\.1\.(\d+)\.(.+?)\s*=\s*(.+)', line
        )
        if match:
            oid_type = int(match.group(1))
            oid_suffix = match.group(2)
            value = match.group(3).strip()
            # Strip STRING: prefix and surrounding quotes
            value = re.sub(r'^(STRING|INTEGER|Gauge32|Counter32):\s*', '', value).strip('"')

            extend_name = decode_oid_suffix(oid_suffix)
            if not extend_name:
                continue

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

        # Output OIDs (3.1.*)
        match = re.match(
            r'iso\.3\.6\.1\.4\.1\.8072\.1\.3\.2\.3\.1\.\d+\.(.+?)\s*=\s*(.+)', line
        )
        if match:
            oid_suffix = match.group(1)
            output_value = match.group(2).strip()
            output_value = re.sub(r'^(STRING|INTEGER|Gauge32):\s*', '', output_value).strip('"')

            extend_name = decode_oid_suffix(oid_suffix)
            if extend_name and 'output' not in extends[extend_name]:
                extends[extend_name]['output'] = output_value

        # Result code OIDs (4.1.4.*)
        match = re.match(
            r'iso\.3\.6\.1\.4\.1\.8072\.1\.3\.2\.4\.1\.4\.(.+?)\s*=\s*INTEGER:\s*(\d+)', line
        )
        if match:
            oid_suffix = match.group(1)
            result = int(match.group(2))
            extend_name = decode_oid_suffix(oid_suffix)
            if extend_name:
                extends[extend_name]['result'] = result

    return extends


def pretty_print_extends(extends, community, target):
    """Pretty print discovered extends."""
    if not extends:
        print("[!] No extends found")
        return

    print(f"\n[+] Found {len(extends)} SNMP extend(s):\n")

    for name, data in sorted(extends.items()):
        print("═" * 60)
        print(f"  Name    : {name}")
        print("─" * 60)

        if 'command' in data:
            print(f"  Command : {data['command']}")
        if 'args' in data and data['args']:
            print(f"  Args    : {data['args']}")
        if 'run_type' in data:
            run_types = {'1': 'run-on-read', '2': 'run-on-set', '3': 'run-periodically'}
            print(f"  Run     : {run_types.get(data['run_type'], data['run_type'])}")
        if 'exec_type' in data:
            exec_types = {'1': 'exec', '2': 'shell'}
            print(f"  Exec    : {exec_types.get(data['exec_type'], data['exec_type'])}")
        if 'output' in data:
            print(f"  Output  : {data['output']}")
        if 'result' in data:
            result_msg = "Success" if data['result'] == 0 else f"Failed (code {data['result']})"
            print(f"  Result  : {result_msg}")

        # Print the correct OID to query this extend's output
        suffix = name_to_oid_suffix(name)
        output_oid = f"1.3.6.1.4.1.8072.1.3.2.3.1.1.{suffix}"
        print(f"  OID     : {output_oid}")
        print(f"  Query   : snmpget -v2c -c {community} {target} {output_oid}")
        print()


def run_snmpwalk(target, community, version):
    """Execute snmpwalk against the NET-SNMP-EXTEND-MIB subtree and return output."""
    try:
        cmd = [
            'snmpwalk',
            f'-v{version}',
            '-c', community,
            target,
            '1.3.6.1.4.1.8072.1.3.2'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0:
            print(f"[!] snmpwalk failed: {result.stderr.strip()}")
            return None

        return result.stdout
    except FileNotFoundError:
        print("[!] snmpwalk not found — install with: apt-get install snmp")
        return None
    except subprocess.TimeoutExpired:
        print("[!] snmpwalk timed out")
        return None
    except Exception as e:
        print(f"[!] Error running snmpwalk: {e}")
        return None


def build_parser():
    parser = argparse.ArgumentParser(
        prog='snmp_extend_parser.py',
        description=(
            'Enumerate and decode NET-SNMP extend entries (NET-SNMP-EXTEND-MIB).\n'
            'Discovers configured extend commands, their arguments, and any cached output.\n\n'
            'The tool queries OID 1.3.6.1.4.1.8072.1.3.2 and decodes the length-prefixed\n'
            'ASCII OID suffixes used to identify each extend by name.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'examples:\n'
            '  %(prog)s 192.168.1.1\n'
            '  %(prog)s 192.168.1.1 -c internal -v 1\n'
            '  snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.4.1.8072.1.3.2 | %(prog)s --stdin\n\n'
            'output OID format:\n'
            '  1.3.6.1.4.1.8072.1.3.2.3.1.1.<len>.<ascii bytes>\n'
            '  e.g. extend named "run" -> 1.3.6.1.4.1.8072.1.3.2.3.1.1.3.114.117.110\n\n'
            'useful follow-up:\n'
            '  snmpset -v2c -c <community> <target> \\\n'
            '    1.3.6.1.4.1.8072.1.3.2.1.0 i 1   # trigger run-on-set extends'
        )
    )

    parser.add_argument(
        'target',
        nargs='?',
        help='Target IP address or hostname'
    )
    parser.add_argument(
        '-c', '--community',
        default='public',
        metavar='STRING',
        help='SNMP community string (default: public)'
    )
    parser.add_argument(
        '-v', '--version',
        default='2c',
        choices=['1', '2c', '3'],
        metavar='VER',
        help='SNMP version: 1, 2c, or 3 (default: 2c)'
    )
    parser.add_argument(
        '--stdin',
        action='store_true',
        help='Read snmpwalk output from stdin instead of running snmpwalk'
    )
    parser.add_argument(
        '--raw',
        action='store_true',
        help='Also print raw snmpwalk output before parsing'
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.stdin:
        raw = sys.stdin.read()
        target = 'stdin'
        community = args.community
    else:
        if not args.target:
            parser.print_help()
            sys.exit(1)

        target = args.target
        community = args.community
        print(f"[*] Querying SNMP extends on {target} (community='{community}', v{args.version})...")
        raw = run_snmpwalk(target, community, args.version)

        if not raw:
            sys.exit(1)

        print(f"[+] Received {len(raw)} bytes")

    if args.raw:
        print("\n[*] Raw output:")
        print(raw)

    extends = parse_snmpwalk_output(raw)
    pretty_print_extends(extends, community, target)


if __name__ == '__main__':
    main()
