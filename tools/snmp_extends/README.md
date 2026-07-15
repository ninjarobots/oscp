# snmp_extend_parser

Enumerate and decode NET-SNMP extend entries from the `NET-SNMP-EXTEND-MIB` subtree. Useful during penetration tests when SNMP is exposed — extend entries often reveal commands running as root or other privileged users.

## What it does

Queries `OID 1.3.6.1.4.1.8072.1.3.2` via `snmpwalk` and decodes the length-prefixed ASCII OID suffixes used to identify each extend by name. For each extend found it shows:

- The command and arguments configured
- How and when it runs (on-read, on-set, periodically)
- Any cached output from the last execution
- The correct OID and `snmpget` command to trigger/retrieve output

## Why this exists

The OID suffix encoding (`<length>.<ascii bytes>`) makes raw `snmpwalk` output hard to read and easy to misparse. Tools like `snmp-check` and `onesixtyone` don't decode extend names or show the associated commands. This tool does.

## Requirements

```bash
apt-get install snmp          # provides snmpwalk/snmpget
pip install nothing           # pure stdlib, no dependencies
```

## Usage

```
usage: snmp_extend_parser.py [-h] [-c STRING] [-v VER] [--stdin] [--raw] [target]

positional arguments:
  target          Target IP address or hostname

options:
  -h, --help      show this help message and exit
  -c STRING       SNMP community string (default: public)
  -v VER          SNMP version: 1, 2c, or 3 (default: 2c)
  --stdin         Read snmpwalk output from stdin instead of running snmpwalk
  --raw           Also print raw snmpwalk output before parsing
```

## Examples

**Basic scan with default community string:**
```bash
python3 snmp_extend_parser.py 192.168.1.1
```

**Custom community string and version:**
```bash
python3 snmp_extend_parser.py 192.168.1.1 -c internal -v 1
```

**Pipe existing snmpwalk output:**
```bash
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.4.1.8072.1.3.2 | python3 snmp_extend_parser.py --stdin
```

**Save snmpwalk output and parse later:**
```bash
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.4.1.8072.1.3.2 > extends.txt
cat extends.txt | python3 snmp_extend_parser.py --stdin
```

## Example output

```
[*] Querying SNMP extends on 192.168.1.1 (community='public', v2c)...
[+] Received 1842 bytes

[+] Found 2 SNMP extend(s):

════════════════════════════════════════════════════════════
  Name    : RESET
────────────────────────────────────────────────────────────
  Command : /bin/bash
  Args    : -c id
  Run     : run-on-read
  Exec    : shell
  Output  : uid=0(root) gid=0(root) groups=0(root)
  Result  : Success
  OID     : 1.3.6.1.4.1.8072.1.3.2.3.1.1.5.82.69.83.69.84
  Query   : snmpget -v2c -c public 192.168.1.1 1.3.6.1.4.1.8072.1.3.2.3.1.1.5.82.69.83.69.84
```

## OID reference

| Subtree | Description |
|---|---|
| `1.3.6.1.4.1.8072.1.3.2.2.1.*` | Extend configuration (command, args, run type) |
| `1.3.6.1.4.1.8072.1.3.2.3.1.*` | Extend output (stdout lines) |
| `1.3.6.1.4.1.8072.1.3.2.4.1.*` | Extend result codes |

**OID suffix encoding:**
```
<length>.<ascii byte>.<ascii byte>...
e.g. "run" -> 3.114.117.110
e.g. "RESET" -> 5.82.69.83.69.84
```

## Follow-up commands

**Trigger a run-on-read extend:**
```bash
snmpget -v2c -c public 192.168.1.1 1.3.6.1.4.1.8072.1.3.2.3.1.1.<suffix>
```

**Trigger run-on-set extends:**
```bash
snmpset -v2c -c public 192.168.1.1 1.3.6.1.4.1.8072.1.3.2.1.0 i 1
```

**Brute force community strings first if needed:**
```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 192.168.1.1
```
