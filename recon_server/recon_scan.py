#!/usr/bin/env python3
"""
recon_scan.py — SEC200/OSCP recon automation
Usage: sudo python3 recon_scan.py <project_name> <target_file> [-t threads] [-p ports]

Running the same project_name again merges new results into the existing
project instead of overwriting it — index.html, the notes summary, and
already-written per-host Obsidian notes are all preserved/updated in place.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

try:
    import nmap
except ImportError:
    print("[-] python-nmap not found. Install with: pip install python-nmap")
    sys.exit(1)

try:
    from recon_common import (
        R, G, Y, C, B, X, log, ok, warn, err, h, classify, svc_badge, CSS,
        manifest_path, load_manifest, save_manifest, merge_scan_results,
        render_flag_chips, ensure_project_dirs, chown_project_dir,
        write_creds_files, write_targets_file, nmap_needs_sudo,
    )
except ImportError:
    print("[-] recon_common.py not found. Keep it in the same directory as recon_scan.py")
    sys.exit(1)

BANNER = f"""{G}
  ____                      ____  _           
 |  _ \\ ___  ___ ___  _ __ / ___|| | ____ ___ 
 | |_) / _ \\/ __/ _ \\| '_ \\\\___ \\| |/ / _` __|
 |  _ <  __/ (_| (_) | | | |___) |   < (_| |  
 |_| \\_\\___|\\___|\\___/|_| |_|____/|_|\\_\\__,_|  
{X}
  SEC200/OSCP Recon Automation — @1B4
"""

ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mKHF]')

# ── Arg parsing ───────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description='SEC200/OSCP recon automation')
    p.add_argument('project', help='Project name — creates ./<project>/ with scans/ and notes/ subdirs. '
                                    'Re-running with the same project name merges new results in.')
    p.add_argument('target_file', help='File with one IP/hostname per line')
    p.add_argument('-t', '--threads', type=int, default=5)
    p.add_argument('-p', '--ports',   default='--top-ports 10000',
                   help='Nmap port args (default: --top-ports 10000)')
    p.add_argument('--no-udp', action='store_true', default=False,
                   help='Skip UDP scan phase (UDP scanning requires root)')
    p.add_argument('--proxy-port', type=int, default=9050,
                   help='SOCKS port to use via proxychains for targets with no direct route in the '
                        'kernel routing table (e.g. reachable only through an SSH -D / chisel-style '
                        'SOCKS tunnel, not a route-based one like ligolo-ng). Default: 9050. Every '
                        'scan checks routability per-target automatically — this only matters for '
                        'targets that actually need the proxy fallback.')
    return p.parse_args()

# ── Preflight ─────────────────────────────────────────────────────────────────
def preflight(args):
    if not shutil.which('nmap'):
        err("nmap not found")
    if not shutil.which('searchsploit'):
        warn("searchsploit not found — exploit phase will be skipped")

    targets_path = Path(args.target_file)
    if not targets_path.exists():
        err(f"Targets file not found: {args.target_file}")

    targets = [
        line.strip() for line in targets_path.read_text().splitlines()
        if line.strip() and not line.strip().startswith('#')
    ]
    if not targets:
        err("No valid targets found")

    out = Path(args.project)
    is_incremental = (out / 'index.html').exists()
    ensure_project_dirs(out)

    if is_incremental:
        ok(f"Existing project: {B}{out}{X} — new results will be merged in")
    else:
        ok(f"New project: {B}{out}{X}")
    ok(f"Targets loaded: {len(targets)}")
    return targets, out

# High-value UDP ports — focused list keeps scan times reasonable.
# Full UDP sweep (-sU -p-) can take 20+ min per host; this covers the
# ports that actually matter for OSCP/SEC200 labs.
UDP_PORTS = [
    53,    # DNS
    67,    # DHCP server
    68,    # DHCP client
    69,    # TFTP
    111,   # RPC portmapper
    123,   # NTP
    137,   # NetBIOS Name Service
    138,   # NetBIOS Datagram
    139,   # NetBIOS Session (also TCP but UDP variant exists)
    161,   # SNMP
    162,   # SNMP trap
    389,   # LDAP (UDP variant)
    445,   # SMB (UDP variant)
    500,   # IKE/IPSec
    514,   # Syslog
    623,   # IPMI/BMC
    631,   # IPP (printing)
    1194,  # OpenVPN
    1434,  # MS SQL Monitor
    1900,  # UPnP/SSDP — included for discovery but filtered from searchsploit
    4500,  # IPSec NAT-T
    5353,  # mDNS
    49152, # Windows RPC dynamic (common start)
]
UDP_PORT_ARG = ','.join(str(p) for p in UDP_PORTS)

# ── Proxy routing (ligolo-ng/sshuttle-style tunnels vs SOCKS proxychains) ──────
def has_specific_route(target: str) -> bool:
    """
    True if the kernel routing table has a route to target more specific
    than the generic default route — either the host is genuinely
    on-link, or you've already set up a route-based tunnel for it
    (ligolo-ng `ip route add 10.5.5.0/24 dev ligolo`, sshuttle, etc), so
    nmap can just reach it directly with no proxy involved.

    False means the ONLY way there is the default route, which on a
    typical OSCP attack box just goes out the VPN adapter and won't
    actually reach an internal pivot target — that's the signal to wrap
    the scan in proxychains instead (dynamic SSH/chisel-style SOCKS
    tunnels don't add a kernel route, so they'd never show up here).

    A CIDR target (e.g. scanning a whole /24) is treated as needing a
    specific route for the network address itself — if that's not
    routable, the same all-hosts-covered-by-a-tunnel logic still applies.
    Fails safe (returns False -> use proxy) if the check itself fails for
    any reason, e.g. `ip` not found, non-Linux host, permission issue.
    """
    try:
        addr = ipaddress.ip_network(target, strict=False).network_address
    except ValueError:
        return False

    try:
        result = subprocess.run(
            ['ip', '-4', 'route', 'show'],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode != 0:
            return False
        for line in result.stdout.splitlines():
            prefix = line.split()[0] if line.split() else ''
            if not prefix or prefix == 'default':
                continue
            try:
                net = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue
            # Belt-and-suspenders: skip any /0 catch-all regardless of how
            # it's written. `ip route show` conventionally prints the
            # default route as the literal word "default", but treating
            # 0.0.0.0/0 as "specific" here would make this function return
            # True for every possible target — silently defeating the
            # entire point of this check — so don't rely on the string
            # match alone.
            if net.prefixlen == 0:
                continue
            if addr in net:
                return True
        return False
    except Exception:
        return False


def _proxied_nmap_scan(nm, target, cmd_args, xml_path, proxy_port):
    """
    Runs `proxychains -q -f <temp config for proxy_port> nmap <cmd_args>`
    directly (bypassing python-nmap's own scan() call, which has no way to
    prefix the binary with proxychains) and feeds the resulting XML back
    into the given PortScanner object via analyse_nmap_xml_scan — so the
    rest of the pipeline sees the exact same kind of object either way,
    proxied or not.

    A temp config is generated per call (rather than relying on whatever
    /etc/proxychains.conf already has) so --proxy-port actually controls
    which port gets used instead of being silently ignored. SOCKS5 is
    assumed — that's what SSH dynamic port forwarding (`ssh -D`) and
    chisel both expose, which is the realistic case here (a route-based
    tunnel like ligolo-ng wouldn't hit this code path at all, since
    has_specific_route() would already be True for it).
    """
    import tempfile
    config = f"strict_chain\nproxy_dns\n[ProxyList]\nsocks5 127.0.0.1 {proxy_port}\n"
    with tempfile.NamedTemporaryFile('w', suffix='.proxychains.conf', delete=False) as f:
        f.write(config)
        config_path = f.name

    try:
        proc = subprocess.run(
            ['proxychains', '-q', '-f', config_path, 'nmap'] + cmd_args + ['-oX', str(xml_path), target],
            capture_output=True, text=True
        )
    finally:
        try:
            os.unlink(config_path)
        except OSError:
            pass

    if not xml_path.exists():
        raise RuntimeError(f"proxychains nmap produced no output (exit {proc.returncode}): {proc.stderr[-300:]}")
    nm.analyse_nmap_xml_scan(nmap_xml_output=xml_path.read_text(encoding='utf-8', errors='ignore'))
    return nm


# ── Nmap scan ─────────────────────────────────────────────────────────────────
def scan_tcp(target, out_dir, port_args, proxy_port=9050):
    """TCP service version scan with default scripts."""
    safe     = target.replace('/', '_').replace('.', '-')
    xml_path = out_dir / 'scans' / 'nmap' / f"{safe}.xml"

    nm = nmap.PortScanner()
    needs_proxy = not has_specific_route(target)
    try:
        if needs_proxy:
            # -Pn: ping-based discovery doesn't work through a SOCKS proxy
            # (no raw ICMP), so skip it and just assume the host is up.
            # -sT: proxychains can only intercept userspace connect() calls
            # — nmap's default SYN scan uses a raw socket that bypasses it
            # entirely, so a SYN scan through proxychains silently returns
            # nothing useful. TCP connect scan is the only mode that
            # actually works here.
            warn(f"{target}: no specific route found — routing this scan through "
                 f"proxychains (SOCKS on port {proxy_port}, forcing -sT)")
            cmd_args = ['-sT', '-sV', '-sC', '-Pn'] + port_args.split() + ['--open']
            nm = _proxied_nmap_scan(nm, target, cmd_args, xml_path, proxy_port)
        else:
            nm.scan(hosts=target, arguments=f"-sV -sC -Pn {port_args} --open", sudo=nmap_needs_sudo())
            nm.csv()
            subprocess.run(
                ['nmap', '-sV', '-sC', '-Pn'] + port_args.split() +
                ['--open', '-oX', str(xml_path), target],
                capture_output=True, text=True
            )
    except Exception as e:
        warn(f"TCP scan error for {target}: {e}")
        return None
    return nm


def scan_udp(target, out_dir, proxy_port=9050):
    """UDP scan against high-value ports. Requires root.

    Skipped entirely for proxied targets — proxychains only handles TCP
    connect() calls, there's no way to tunnel a UDP scan through it, so
    attempting one would just hang or silently return nothing.
    """
    if not has_specific_route(target):
        warn(f"{target}: no specific route — skipping UDP (can't be tunneled through proxychains)")
        return None

    safe     = target.replace('/', '_').replace('.', '-')
    xml_path = out_dir / 'scans' / 'nmap' / f"{safe}_udp.xml"

    nm_udp = nmap.PortScanner()
    try:
        nm_udp.scan(
            hosts=target,
            arguments=f"-sU -sV -Pn --open -p {UDP_PORT_ARG}",
            sudo=nmap_needs_sudo()
        )
        nm_udp.csv()
        subprocess.run(
            ['nmap', '-sU', '-sV', '-Pn', '--open',
             '-p', UDP_PORT_ARG,
             '-oX', str(xml_path), target],
            capture_output=True, text=True
        )
    except Exception as e:
        warn(f"UDP scan error for {target}: {e}")
        return None
    return nm_udp


def merge_scans(nm_tcp, nm_udp, host):
    """
    Merge UDP results into the TCP PortScanner object so the rest of the
    pipeline (query generation, HTML rendering, Obsidian notes) sees one
    unified view of the host.
    """
    if nm_udp is None or host not in nm_udp.all_hosts():
        return nm_tcp
    if host not in nm_tcp.all_hosts():
        return nm_tcp

    udp_ports = nm_udp[host].get('udp', {})
    if not udp_ports:
        return nm_tcp

    # Inject UDP ports into the TCP scanner's host data
    if 'udp' not in nm_tcp[host]:
        nm_tcp[host]['udp'] = {}
    for port, data in udp_ports.items():
        if data.get('state') in ('open', 'open|filtered'):
            nm_tcp[host]['udp'][port] = data

    return nm_tcp


def scan_target(target, out_dir, port_args, do_udp=True, proxy_port=9050):
    safe = target.replace('/', '_').replace('.', '-')
    log(f"Scanning TCP: {target}")

    nm = scan_tcp(target, out_dir, port_args, proxy_port=proxy_port)
    if nm is None:
        return None, safe

    ok(f"TCP done: {target}")

    if do_udp:
        log(f"Scanning UDP: {target}")
        nm_udp = scan_udp(target, out_dir, proxy_port=proxy_port)
        if nm_udp is not None:
            udp_count = len(nm_udp[target].get('udp', {})) if target in nm_udp.all_hosts() else 0
            ok(f"UDP done: {target} ({udp_count} open|filtered port(s))")
            nm = merge_scans(nm, nm_udp, target)
        else:
            warn(f"UDP scan failed for {target} — TCP results only")

    return nm, safe

# ── Query generation ──────────────────────────────────────────────────────────
# Only generate specific product+version queries.
# No OS-level fallbacks, no bare product names without a version.
# This keeps results focused and prevents 10K-result noise.

# Terms that are too generic to search alone
SKIP_ALONE = {
    # Protocol/service names — too generic without a product attached
    'tcpwrapped', 'unknown', 'generic', 'ssl', 'tls',
    'http', 'https', 'ftp', 'ssh', 'smtp', 'pop3', 'imap',
    'snmp', 'rdp', 'smb', 'rpc', 'msrpc', 'netbios',
    'ldap', 'kerberos', 'httpd', 'upnp', 'ssdp', 'igmp',
    'nat-pmp', 'mdns', 'llmnr', 'ntp',
    # OS names — CPE o: entries that bleed into queries
    'windows', 'linux', 'unix', 'macos', 'darwin', 'android',
    # Vendor names alone — meaningless without a product
    'microsoft', 'apache', 'open', 'gnu', 'canonical',
    'ubuntu', 'debian', 'centos', 'redhat', 'oracle',
    'sun', 'cisco', 'vmware',
}

# ── Banner/script version extraction ─────────────────────────────────────────
# Some services obscure their version in the protocol negotiation but leak the
# real version in banner text captured by NSE scripts.
# e.g. vsftpd reports "2.0.8 or later" but banner says "220 (vsFTPd 2.3.4)"
#      OpenSSH reports "7.6p1" but banner says "SSH-2.0-OpenSSH_8.2p1"

# Patterns to try against script output, in priority order.
# Each is (regex, group_index_for_version)
BANNER_VERSION_PATTERNS = [
    # FTP 220 banner: "220 (vsFTPd 2.3.4)" or "220 ProFTPD 1.3.5 Server"
    re.compile(r'220[- (]*([\w]+?)[/ _v]+(\d+\.\d+[\w.]*)', re.IGNORECASE),
    # SSH banner: "SSH-2.0-OpenSSH_8.2p1"
    re.compile(r'SSH-[\d.]+-(\w+)[_/](\d+\.\d+[\w.]*)', re.IGNORECASE),
    # Slash-separated only: "product/2.3.4" — avoids space-separated IP false-positives
    re.compile(r'([\w][\w\-]+)/(\d+\.\d+[\w.]*)'),
]

# Matches an IPv4 address — used to reject false version matches from banners
IP_RE      = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
# Valid version: X.Y or X.Y.Z[suffix], max 4 dotted segments
VERSION_RE = re.compile(r'^\d+\.\d+(\.\d+){0,2}[a-zA-Z0-9]*$')

def is_plausible_version(s):
    """True if s looks like a version number and not an IP address."""
    return bool(VERSION_RE.match(s)) and not bool(IP_RE.match(s))

# Strings that indicate nmap is guessing rather than reporting
UNCERTAIN_VERSION_MARKERS = [
    'or later', 'or newer', 'or higher', '+', 'and later',
]

def is_uncertain_version(version_str):
    """Return True if nmap's version string is a guess rather than exact."""
    v = version_str.lower()
    return any(m in v for m in UNCERTAIN_VERSION_MARKERS)

def extract_real_version(product, version, scripts):
    """
    Try to find a more specific version than what nmap reported.
    Checks NSE script output for banner strings containing product/version.
    Returns (product, real_version) — falls back to originals if nothing found.
    """
    if not scripts or not is_uncertain_version(version):
        return product, version

    product_lower = product.lower()

    for scr_id, scr_out in scripts.items():
        if not scr_out:
            continue
        for line in scr_out.splitlines():
            for pattern in BANNER_VERSION_PATTERNS:
                m = pattern.search(line)
                if not m:
                    continue
                banner_product = m.group(1).lower()
                banner_version = m.group(2)

                # Reject anything that looks like an IP address or implausible version
                if not is_plausible_version(banner_version):
                    continue

                # Accept only if banner product name overlaps with nmap product
                prod_words = set(re.split(r'[\W_]+', product_lower))
                if any(w in banner_product for w in prod_words if len(w) > 2):
                    return product, banner_version

    return product, version  # No better version found



def build_queries(nm, host):
    """
    Build a deduplicated list of specific searchsploit queries for a host.
    Only emits product+version pairs — never bare product names or OS strings.
    """
    queries = []
    seen = set()

    def add(q):
        q = q.strip()
        if q and q.lower() not in seen and len(q) > 4:
            seen.add(q.lower())
            queries.append(q)

    if host not in nm.all_hosts():
        return queries

    for proto in nm[host].all_protocols():
        for port in nm[host][proto]:
            svc = nm[host][proto][port]
            product  = svc.get('product', '').strip()
            version  = svc.get('version', '').strip()
            extra    = svc.get('extrainfo', '').strip()
            cpe_list = svc.get('cpe', '').strip()
            scripts  = svc.get('script', {})

            # Use banner/script output to get the real version when nmap
            # reports something vague like "2.0.8 or later"
            product, version = extract_real_version(product, version, scripts)

            # Only query if we have both product and version,
            # and the product isn't a generic OS/vendor-only term
            if product and version and product.lower() not in SKIP_ALONE:
                # Full product + version
                add(f"{product} {version}")

                # Strip leading generic vendor word and retry
                # e.g. "Microsoft IIS httpd" -> "IIS httpd 10.0"
                words = product.split()
                if len(words) > 1 and words[0].lower() in SKIP_ALONE:
                    remainder = ' '.join(words[1:])
                    # Only add if the remainder itself isn't also generic
                    if remainder.lower() not in SKIP_ALONE:
                        add(f"{remainder} {version}")

            # CPE gives the cleanest structured identifier
            # cpe:/a:vendor:product:version  or  cpe:/o:vendor:os:version
            for cpe in cpe_list.split():
                parts = re.sub(r'^cpe:/[ao]:', '', cpe).split(':')
                # Need at least vendor:product:version — skip OS-level CPEs
                # that have no version (e.g. cpe:/o:microsoft:windows)
                if len(parts) >= 3 and parts[2]:
                    prod = parts[1].lower()
                    # Skip generic terms that produce useless queries
                    if prod not in SKIP_ALONE:
                        add(f"{parts[1]} {parts[2]}")
                # vendor:product with version from nmap field — only if
                # product name is specific enough to be worth querying
                elif len(parts) >= 2 and version:
                    prod = parts[1].lower()
                    if prod not in SKIP_ALONE and len(prod) > 3:
                        add(f"{parts[1]} {version}")

            # extrainfo sometimes has "Samba 4.x" or "mod_ssl/2.4.x"
            # Only use slash-style strings (product/version) — not bare words
            if extra and version:
                slash = re.match(r'^(\w[\w\-]+)/(\d+[\d.]+)', extra)
                if slash and slash.group(1).lower() not in SKIP_ALONE:
                    add(f"{slash.group(1)} {slash.group(2)}")

    return queries

# ── Searchsploit ──────────────────────────────────────────────────────────────
def run_searchsploit(nm, host, safe, out_dir):
    if not shutil.which('searchsploit'):
        return 0

    queries = build_queries(nm, host)
    if queries:
        log(f"  Queries for {host}: {queries}")
    if not queries:
        ss_path = out_dir / 'scans' / 'searchsploit' / f"{safe}.txt"
        ss_path.write_text("No specific service versions detected.\n")
        return 0

    results = []
    for query in queries:
        try:
            r = subprocess.run(
                ['searchsploit', query],
                capture_output=True, text=True, timeout=30
            )
            output = r.stdout
        except subprocess.TimeoutExpired:
            continue

        # Save raw output per query
        results.append(f"--- Query: {query} ---\n{output}\n")

    ss_path = out_dir / 'scans' / 'searchsploit' / f"{safe}.txt"
    ss_path.write_text(
        f"=== Searchsploit Results: {safe} ===\n"
        f"Scanned: {datetime.now()}\n\n"
        + ''.join(results)
    )

    hit_count = parse_ss_hits(ss_path)[1]
    ok(f"Searchsploit: {host} ({hit_count} hit(s))")
    return hit_count

# ── Searchsploit parser ───────────────────────────────────────────────────────
def parse_version(v):
    """
    Parse a version string into a comparable tuple of (number, suffix) pairs
    — e.g. "8.2p1" -> ((8, ''), (2, 'p1')), "2.4.49" -> ((2, ''), (4, ''), (49, '')).

    Every element is always the same (int, str) shape, specifically so two
    parsed versions can always be compared with <, <=, etc. without risking
    "'<' not supported between instances of 'str' and 'int'" — which is
    exactly what happened before this fix whenever a version with a letter
    suffix (very common — OpenSSH "8.2p1" on Debian/Ubuntu is a textbook
    case) got compared against a plain numeric one like "8.2.51" from a
    searchsploit title. Comparing (int, str) tuples compares the numeric
    part first, then the suffix as a tiebreaker, which preserves the
    original intent while being safe for every input.
    """
    v = v.strip().lower()
    parts = re.split(r'[.\-]', v)
    result = []
    for p in parts:
        m = re.match(r'(\d+)(.*)', p)
        if m:
            result.append((int(m.group(1)), m.group(2) or ''))
        elif p:
            result.append((0, p))  # pure non-numeric segment (e.g. "beta")
    return tuple(result) if result else ((0, ''),)

def version_in_range(query_ver, title):
    """
    Check if query_ver falls within any version range expressed in the title.
    Handles common exploit title patterns:
      - "< 2.4.51"              (less than)
      - "<= 2.4.51"             (less than or equal)
      - "> 2.0 < 2.4.51"        (between, with or without comma)
      - "2.4.17 - 2.4.51"       (explicit numeric range)
      - "3.x - 4.x"             (major.x wildcard range)
      - "through 8.3" / "before 8.3"
    Returns True/False if a range expression was found and evaluated,
    None if no range expression found (caller falls back to exact match).
    """
    t = title.lower()
    qv = parse_version(query_ver)

    # ── Explicit numeric dash-range: "2.4.17 - 2.4.51" ──────────────────────
    # Must have digits on both sides; x-wildcards handled separately below.
    # Match greedily so "2.4.17 - 2.4.51" doesn't get confused with a single
    # version number that happens to have a dash.
    dash_m = re.search(
        r'(\d+\.\d+[\d.]*?)\s*[-–]\s*(\d+\.\d+[\d.]*?)(?:\s|$|[^\d.])', t
    )
    if dash_m:
        lo = parse_version(dash_m.group(1))
        hi = parse_version(dash_m.group(2))
        if lo != hi:  # skip "X.Y - Z" that's really just a title dash
            # Compare at the precision of the bounds
            depth = max(len(lo), len(hi))
            qv_p  = (qv + ((0, ''),) * depth)[:depth]
            lo_p  = (lo + ((0, ''),) * depth)[:depth]
            hi_p  = (hi + ((0, ''),) * depth)[:depth]
            return lo_p <= qv_p <= hi_p

    # ── Wildcard range: "3.x - 4.x" or "2.3.x - 2.4.x" ────────────────────
    wild_m = re.search(
        r'(\d+(?:\.\d+)*)\.x\s*[-–]\s*(\d+(?:\.\d+)*)\.x', t
    )
    if wild_m:
        lo = parse_version(wild_m.group(1))
        hi = parse_version(wild_m.group(2))
        depth = max(len(lo), len(hi))
        qv_p  = (qv + ((0, ''),) * depth)[:depth]
        lo_p  = (lo + ((0, ''),) * depth)[:depth]
        hi_p  = (hi + ((0, ''),) * depth)[:depth]
        return lo_p <= qv_p <= hi_p

    # ── "through X" / "before X" / "up to X" ────────────────────────────────
    kw_m = re.search(r'(?:through|before|up to)\s+(\d+[\d.p]+)', t)
    if kw_m:
        return qv <= parse_version(kw_m.group(1))

    # ── Explicit inequality operators: "< X", "<= X", "> X < Y" etc. ────────
    # Collect all operators and their versions in order
    ops = re.findall(r'([<>][=]?)\s*(\d+[\d.p]+)', t)
    if ops:
        upper = [(op, parse_version(v)) for op, v in ops if op in ('<', '<=')]
        lower = [(op, parse_version(v)) for op, v in ops if op in ('>', '>=')]
        result = True
        for op, rv in upper:
            result = result and (qv <= rv if op == '<=' else qv < rv)
        for op, rv in lower:
            result = result and (qv >= rv if op == '>=' else qv > rv)
        # Only return if we actually found operators (not just from a version number)
        if upper or lower:
            return result

    return None  # No range expression found

def extract_version_from_query(query):
    """
    Pull version number(s) from a query string.
    e.g. "Apache httpd 2.4.49" -> ["2.4.49", "2.4"]
    Returns list of version strings, most specific first.
    """
    tokens = re.findall(r'\b(\d+\.\d+[\w.]*)\b', query)
    versions = []
    for t in tokens:
        versions.append(t)
        short = re.match(r'(\d+\.\d+)', t)
        if short and short.group(1) != t:
            versions.append(short.group(1))
    return versions

def version_matches_title(versions, title):
    """
    Return True if the queried version matches the exploit title, either by:
      1. Exact/token match  — "2.4.49" found in title as a discrete token
      2. Range match        — title contains "< 2.4.51", "2.3.x - 2.4.x", etc.
                              and the queried version falls within that range
    Rejects titles that mention a completely different version with no range.
    """
    if not versions:
        return True

    t = title.lower()
    primary = versions[0]  # Most specific version from query

    # 1. Try range expressions first using the primary (most specific) version
    range_result = version_in_range(primary, title)
    if range_result is not None:
        return range_result

    # 2. Fall back to exact token match for any version variant
    for v in versions:
        pattern = re.escape(v.lower()) + r'(?![\d\.])'
        if re.search(pattern, t):
            return True

    return False

def parse_ss_hits(ss_path):
    """
    Parse searchsploit output file.
    Post-filters results so only entries whose title contains the queried
    version number are kept — eliminates fuzzy cross-version noise.
    Returns (groups_dict, total_hit_count).
    groups_dict: { query_str: [ {id, title, path}, ... ] }
    """
    if not ss_path.exists():
        return {}, 0

    content = ss_path.read_text(encoding='utf-8', errors='replace')
    groups = {}
    current_query = 'General'
    current_versions = []
    seen_ids = set()
    total = 0

    in_shellcodes   = False  # Track whether we're in the Shellcodes section
    skip_query      = False  # Track whether current query should be ignored

    for raw in content.splitlines():
        line = ANSI_RE.sub('', raw).strip()

        q_match = re.match(r'^--- Query: (.+) ---$', line)
        if q_match:
            current_query = q_match.group(1).strip()
            current_versions = extract_version_from_query(current_query)
            in_shellcodes = False

            # Drop queries that are entirely generic terms with no version.
            # e.g. "SSDP UPnP", "Microsoft Windows RPC", "windows"
            query_words = re.sub(r'[^a-z0-9 ]', '', current_query.lower()).split()
            has_version = bool(current_versions)
            all_generic = all(w in SKIP_ALONE for w in query_words)
            skip_query  = all_generic and not has_version
            continue

        # Skip entire blocks for generic queries
        if skip_query:
            continue

        # Detect section headers
        if 'Shellcode Title' in line or line.startswith('Shellcodes:'):
            in_shellcodes = True
            continue
        if 'Exploit Title' in line or line.startswith('Exploits:'):
            in_shellcodes = False
            continue

        # Skip everything in the shellcodes section
        if in_shellcodes:
            continue

        if re.match(r'^[-= ]+$', line):
            continue
        if any(x in line for x in ['| Path', '| EDB-ID', 'No Results']):
            continue

        # "Some Title text       | platform/type/12345.ext"
        m = re.match(r'^(.+?)\s*\|\s*(\S+/\S+\.\w+)\s*$', line)
        if not m:
            continue

        title = m.group(1).strip()
        path  = m.group(2).strip()
        if not title or title.lower().startswith('exploit title'):
            continue

        # Version filter — drop results that don't mention the queried version
        if not version_matches_title(current_versions, title):
            continue

        id_match = re.search(r'/(\d+)\.\w+$', path)
        edb_id = id_match.group(1) if id_match else ''

        if edb_id in seen_ids:
            continue
        seen_ids.add(edb_id)

        groups.setdefault(current_query, []).append({
            'id': edb_id, 'title': title, 'path': path
        })
        total += 1

    return groups, total

# ── Per-target HTML ───────────────────────────────────────────────────────────
def render_target_html(nm, host, safe, out_dir):
    ss_path = out_dir / 'scans' / 'searchsploit' / f"{safe}.txt"
    ss_groups, exploit_count = parse_ss_hits(ss_path)

    # ── Scan metadata ─────────────────────────────────────────────────────────
    host_data = nm[host] if host in nm.all_hosts() else {}
    hostnames = [e['name'] for e in host_data.get('hostnames', []) if e.get('name')]
    hostname  = hostnames[0] if hostnames else ''
    os_matches = host_data.get('osmatch', [])
    os_guess   = os_matches[0]['name'] if os_matches else ''

    meta_rows = []
    if hostname:
        meta_rows.append(('Hostname', f"<code>{h(hostname)}</code>"))
    if os_guess:
        acc = os_matches[0].get('accuracy', '')
        meta_rows.append(('OS guess', f"{h(os_guess)} ({h(acc)}%)"))
    if host_data.get('addresses', {}).get('mac'):
        mac = host_data['addresses']['mac']
        vendor = host_data.get('vendor', {}).get(mac, '')
        meta_rows.append(('MAC', f"{h(mac)}{f' <span style=chr(34)color:var(--muted){chr(34)}>({h(vendor)})</span>' if vendor else ''}"))

    meta_html = '<table class="meta-table">' + ''.join(
        f"<tr><td>{h(k)}</td><td>{v}</td></tr>" for k, v in meta_rows
    ) + '</table>' if meta_rows else ''

    # ── Port table ────────────────────────────────────────────────────────────
    port_rows = ''
    open_ports = []
    for proto in host_data.all_protocols() if hasattr(host_data, 'all_protocols') else []:
        for port in sorted(host_data[proto].keys()):
            svc = host_data[proto][port]
            if svc.get('state') != 'open':
                continue
            open_ports.append(port)

            name    = svc.get('name', '')
            product = svc.get('product', '')
            version = svc.get('version', '')
            extra   = svc.get('extrainfo', '')
            cpe     = svc.get('cpe', '')

            ver_parts = [product, version]
            if extra:
                ver_parts.append(f"({extra})")
            ver_str = ' '.join(v for v in ver_parts if v)

            cpe_html = ''
            if cpe:
                cpe_html = '<br>' + ' '.join(
                    f"<code style='font-size:10px;color:var(--muted);background:transparent;border:none'>{h(c)}</code>"
                    for c in cpe.split()
                )

            # Script output
            script_html = ''
            for scr_id, scr_out in svc.get('script', {}).items():
                if not scr_out.strip():
                    continue
                script_html += f"""
<div class='script-block'>
  <div class='script-id'>&#9657; {h(scr_id)}</div>
  <div class='script-output'>{h(scr_out.strip())}</div>
</div>"""

            script_row = ''
            if script_html:
                script_row = f"<tr><td colspan='4' style='padding:0 10px 10px 28px;background:var(--surface2)'>{script_html}</td></tr>"

            port_rows += f"""<tr>
  <td><span class='port-num'>{h(port)}/{h(proto)}</span></td>
  <td><span class='badge badge-green' style='font-size:10px'>open</span></td>
  <td>{svc_badge(name)}</td>
  <td><span style='color:var(--text)'>{h(ver_str)}</span>{cpe_html}</td>
</tr>{script_row}"""

    if port_rows:
        ports_html = f"""
<table class='port-table'>
<thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version / Banner</th></tr></thead>
<tbody>{port_rows}</tbody>
</table>"""
    else:
        ports_html = "<p class='empty-msg'>No open ports detected.</p>"

    # ── Searchsploit HTML ─────────────────────────────────────────────────────
    if ss_groups:
        ss_html = ''
        for query, entries in ss_groups.items():
            if not entries:
                continue
            ss_html += f"<div class='query-group'>"
            ss_html += f"<div class='query-label'>Query: {h(query)} &nbsp;<span style='color:var(--green)'>({len(entries)} hit(s))</span></div>"
            for e in entries:
                label, badge_cls = classify(e['title'])
                full_path = f"/usr/share/exploitdb/{e['path']}"
                ss_html += f"""<div class='exploit-row'>
  <span class='exploit-id'>EDB-{h(e['id'])}</span>
  <div>
    <div class='exploit-title'><span class='badge {badge_cls}'>{label}</span> {h(e['title'])}</div>
    <div class='exploit-path'>&#128193; {h(full_path)}</div>
  </div>
</div>"""
            ss_html += "</div>"
    else:
        ss_html = "<p class='empty-msg'>No matching exploits found in local database.</p>"

    exploit_badge = (
        f"<span class='badge badge-red' style='margin-left:8px'>{exploit_count} hit(s)</span>"
        if exploit_count else ''
    )

    # ── Detected web services (for the Feroxbuster protocol/port dropdowns) ──
    web_endpoints = []  # list of (scheme, port), in detection order
    is_dc = False  # LDAP present -> this host is (probably) a domain controller
    LDAP_PORTS = {389, 636, 3268, 3269}
    for proto in host_data.all_protocols() if hasattr(host_data, 'all_protocols') else []:
        for port in sorted(host_data[proto].keys()):
            svc = host_data[proto][port]
            if svc.get('state') != 'open':
                continue
            name = (svc.get('name') or '').lower()
            if 'https' in name or (name == 'ssl' and 'http' in (svc.get('tunnel', '') or '')):
                web_endpoints.append(('https', port))
            elif 'http' in name:
                web_endpoints.append(('http', port))
            if port in LDAP_PORTS or 'ldap' in name:
                is_dc = True

    # ── Feroxbuster card ──────────────────────────────────────────────────────
    # Only shown when we actually detected a web service — no point offering
    # a content-discovery scan against a host with nothing serving HTTP.
    # Deliberately minimal: this is for quick recon, not a full scan config
    # UI — protocol + port (from what we already found) is the whole
    # decision that matters day-to-day. Everything else is a sane default,
    # tucked behind Advanced for the cases that need it. The IP is always
    # this host — there's no reason to ever target a different one from here.
    if web_endpoints:
        detected_ports = sorted(set(port for _, port in web_endpoints))
        default_scheme, default_port = web_endpoints[0]
        port_options = ''.join(
            f'<option value="{p}"{" selected" if p == default_port else ""}>{p}</option>'
            for p in detected_ports
        )
        ferox_section = f"""
  <div class="card">
    <div class="card-header"><h2>&#128270; Feroxbuster</h2></div>
    <div class="card-body">
      <form id="ferox-form" onsubmit="startFerox(event)" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <select class="scan-field" id="ferox-protocol">
          <option value="http"{" selected" if default_scheme == "http" else ""}>http</option>
          <option value="https"{" selected" if default_scheme == "https" else ""}>https</option>
        </select>
        <select class="scan-field" id="ferox-port">{port_options}</select>
        <button type="submit" id="ferox-submit" class="scan-field" style="background:var(--green);color:#0d1117;font-weight:700;cursor:pointer;border:none">Start Scan</button>
        <button type="button" class="scan-field" style="cursor:pointer;background:transparent" onclick="document.getElementById('ferox-advanced').classList.toggle('section-collapsed')">Advanced &#9662;</button>
      </form>
      <div id="ferox-advanced" class="section-collapsed" style="margin-top:10px">
        <div class="scan-options" style="margin-top:0">
          <label>Wordlist <input class="scan-field" id="ferox-wordlist" placeholder="default: dirb/common.txt" style="width:220px"></label>
          <label>Extensions <input class="scan-field" id="ferox-extensions" placeholder="php,txt,bak" style="width:150px"></label>
          <label>Threads <input class="scan-field" id="ferox-threads" type="number" min="1" max="200" placeholder="threads" style="width:80px"></label>
        </div>
        <label style="display:block;margin-top:8px;font-size:12px;color:var(--muted)">
          <input id="ferox-dont-filter" type="checkbox" checked> Disable feroxbuster's own wildcard/soft-404 auto-filter (recommended — it can silently drop real hits)
        </label>
        <label style="display:block;margin-top:4px;font-size:12px;color:var(--muted)">
          <input id="ferox-status-filter" type="checkbox" checked> Only show 2xx/3xx/401 results (uncheck to include 403s, 404s, etc. — a raw scan is mostly 404s, and 403 is often a blanket WAF/deny rule; the full output is always saved to disk either way)
        </label>
      </div>
      <div id="ferox-progress" style="display:none;margin-top:10px">
        <div class="progress-label"><span id="ferox-progress-text"></span></div>
        <pre id="ferox-log" style="margin-top:6px;max-height:150px;overflow-y:auto;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:8px 10px;font-size:11px;color:var(--muted);white-space:pre-wrap"></pre>
      </div>
      <div class="section-toggle" onclick="document.getElementById('ferox-results-wrap').classList.toggle('section-collapsed')">
        <strong style="font-size:13px">Results</strong>
        <span id="ferox-result-count" style="color:var(--muted);font-size:12px"></span>
      </div>
      <div id="ferox-results-wrap">
        <table class="port-table" id="ferox-table" style="margin-top:8px">
          <thead><tr><th>Status</th><th>URL</th><th>Size</th><th>Words</th><th>Lines</th></tr></thead>
          <tbody id="ferox-tbody"><tr><td colspan="5" class="empty-msg">No scan run yet.</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>"""
        ferox_js = """
function renderFeroxHits(hits) {
  const tbody = document.getElementById('ferox-tbody');
  const countEl = document.getElementById('ferox-result-count');
  if (!hits || !hits.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-msg">No scan run yet.</td></tr>';
    if (countEl) countEl.textContent = '';
    return;
  }
  if (countEl) countEl.textContent = '(' + hits.length + ')';
  const statusColor = s => (s >= 200 && s < 300) ? 'badge-green' : (s >= 300 && s < 400) ? 'badge-cyan' : (s === 401 || s === 403) ? 'badge-orange' : 'badge-muted';
  tbody.innerHTML = hits.map(hobj => `
    <tr>
      <td><span class="badge ${statusColor(hobj.status)}">${escapeHtml(hobj.status)}</span></td>
      <td><a href="${escapeHtmlAttr(hobj.url)}" target="_blank" style="color:var(--cyan)">${escapeHtml(hobj.url)}</a></td>
      <td>${escapeHtml(hobj.length)}</td>
      <td>${escapeHtml(hobj.words)}</td>
      <td>${escapeHtml(hobj.lines)}</td>
    </tr>`).join('');
}
function loadFerox() {
  fetch('/api/ferox/' + encodeURIComponent(HOST))
    .then(r => { if (!r.ok) throw new Error('no server'); return r.json(); })
    .then(data => renderFeroxHits(data.hits))
    .catch(() => {
      document.getElementById('ferox-tbody').innerHTML =
        '<tr><td colspan="5" class="empty-msg">Live dashboard required &mdash; run recon_server.py</td></tr>';
    });
}
let feroxPolling = false;
function startFerox(evt) {
  evt.preventDefault();
  const protocol = document.getElementById('ferox-protocol').value;
  const port = document.getElementById('ferox-port').value;
  const url = protocol + '://' + HOST + ':' + port + '/';
  const body = {
    url: url,
    wordlist: document.getElementById('ferox-wordlist').value,
    extensions: document.getElementById('ferox-extensions').value,
    threads: document.getElementById('ferox-threads').value,
    dont_filter: document.getElementById('ferox-dont-filter').checked,
    status_filter: document.getElementById('ferox-status-filter').checked,
  };
  fetch('/api/ferox/' + encodeURIComponent(HOST), {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)
  })
  .then(r => { if (!r.ok) return r.json().then(d => { throw new Error(d.description || 'failed to start scan'); }); return r.json(); })
  .then(() => {
    document.getElementById('ferox-submit').disabled = true;
    document.getElementById('ferox-progress').style.display = 'block';
    feroxPolling = true;
    pollFeroxStatus();
  })
  .catch(e => alert('Could not start feroxbuster: ' + e.message));
}
function pollFeroxStatus() {
  fetch('/api/ferox/status').then(r => r.json()).then(s => {
    document.getElementById('ferox-progress-text').textContent =
      s.running ? ('Scanning ' + (s.url || '') + '\\u2026 ' + (s.hits ? s.hits.length : 0) + ' hit(s) so far') : 'Done';
    document.getElementById('ferox-log').textContent = (s.log || []).slice(-30).join('\\n');
    if (s.hits) renderFeroxHits(s.hits);
    if (s.running) {
      setTimeout(pollFeroxStatus, 1500);
    } else if (feroxPolling) {
      feroxPolling = false;
      document.getElementById('ferox-submit').disabled = false;
      loadFerox();
    }
  }).catch(() => {});
}
loadFerox();
"""
    else:
        ferox_section = ''
        ferox_js = ''

    if is_dc:
        bloodhound_js = """
function renderBloodhoundResults(data) {
  const body = document.getElementById('bloodhound-results-body');
  const countEl = document.getElementById('bloodhound-result-count');
  if (!data || !data.scanned_at) {
    body.innerHTML = '<span class="empty-msg">No scan run yet.</span>';
    if (countEl) countEl.textContent = '';
    return;
  }
  if (countEl) countEl.textContent = '(' + data.scanned_at + ')';
  const summary = data.summary || {};
  const summaryText = Object.keys(summary).length
    ? Object.entries(summary).map(([k, v]) => `${v} ${k}`).join(', ')
    : 'collection complete';
  body.innerHTML = `
    <p style="margin:8px 0">${escapeHtml(summaryText)} &mdash; domain: ${escapeHtml(data.domain || '')}</p>
    <a class="scan-field" style="text-decoration:none;display:inline-block" href="${escapeHtmlAttr(data.zip_url)}" download>&#11015; Download BloodHound ZIP</a>
  `;
}
function loadBloodhound() {
  fetch('/api/bloodhound/' + encodeURIComponent(HOST))
    .then(r => { if (!r.ok) throw new Error('no server'); return r.json(); })
    .then(data => {
      const credSelect = document.getElementById('bloodhound-cred');
      const submitBtn = document.getElementById('bloodhound-submit');
      const hint = document.getElementById('bloodhound-hint');
      const domainField = document.getElementById('bloodhound-domain');

      if (data.credentials && data.credentials.length) {
        credSelect.innerHTML = data.credentials.map(c =>
          `<option value="${escapeHtmlAttr(c.source_host)}::${escapeHtmlAttr(c.cred_id)}">${escapeHtml(c.username)} (${escapeHtml(c.status)}, via ${escapeHtml(c.source_host)})</option>`
        ).join('');
        credSelect.disabled = false;
        submitBtn.disabled = false;
        hint.textContent = 'Pick a credential confirmed to work over LDAP, confirm the domain, and start the scan.';
      } else {
        credSelect.innerHTML = '<option value="">No valid LDAP credentials yet</option>';
        credSelect.disabled = true;
        submitBtn.disabled = true;
        hint.textContent = 'Spray a credential against LDAP (or manually mark one valid for the ldap service) to enable BloodHound collection.';
      }

      if (data.suggested_domain && !domainField.value) {
        domainField.value = data.suggested_domain;
      }

      renderBloodhoundResults(data.last_run);
    })
    .catch(() => {
      document.getElementById('bloodhound-hint').textContent = 'Live dashboard required \u2014 run recon_server.py';
    });
}
let bloodhoundPolling = false;
function startBloodhound(evt) {
  evt.preventDefault();
  const credVal = document.getElementById('bloodhound-cred').value;
  if (!credVal) { alert('No credential selected'); return; }
  const [sourceHost, credId] = credVal.split('::');
  const body = {
    source_host: sourceHost,
    cred_id: credId,
    domain: document.getElementById('bloodhound-domain').value,
    dc: document.getElementById('bloodhound-dc').value,
  };
  fetch('/api/bloodhound/' + encodeURIComponent(HOST), {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)
  })
  .then(r => { if (!r.ok) return r.json().then(d => { throw new Error(d.description || 'failed to start scan'); }); return r.json(); })
  .then(() => {
    document.getElementById('bloodhound-submit').disabled = true;
    document.getElementById('bloodhound-progress').style.display = 'block';
    bloodhoundPolling = true;
    pollBloodhoundStatus();
  })
  .catch(e => alert('Could not start BloodHound scan: ' + e.message));
}
function pollBloodhoundStatus() {
  fetch('/api/bloodhound/status').then(r => r.json()).then(s => {
    document.getElementById('bloodhound-progress-text').textContent = s.running ? 'Collecting\u2026' : 'Done';
    document.getElementById('bloodhound-log').textContent = (s.log || []).slice(-30).join('\\n');
    if (s.running) {
      setTimeout(pollBloodhoundStatus, 1500);
    } else if (bloodhoundPolling) {
      bloodhoundPolling = false;
      document.getElementById('bloodhound-submit').disabled = false;
      loadBloodhound();
    }
  }).catch(() => {});
}
loadBloodhound();
"""
    else:
        bloodhound_js = ''

    # ── Note download / host delete toolbar ──────────────────────────────────
    note_rel_path = f"../../notes/{host}.md"
    host_toolbar = f"""
  <div class="toolbar-row">
    <a class="scan-field" style="text-decoration:none;display:inline-block" href="{h(note_rel_path)}" download>&#11015; Download Obsidian Note</a>
    <button class="scan-field" style="background:var(--red);color:#fff;font-weight:700;cursor:pointer;border:none;margin-left:auto" onclick="deleteHost()">&#128465; Delete Host</button>
  </div>"""

    # ── Credentials card ─────────────────────────────────────────────────────
    creds_section = """
  <div class="card">
    <div class="card-header"><h2>&#128273; Credentials</h2></div>
    <div class="card-body">
      <table class="port-table" id="creds-table">
        <thead><tr><th>User</th><th>Secret</th><th>Type</th><th>Service</th><th>Status</th><th>Notes</th><th></th><th></th></tr></thead>
        <tbody id="creds-tbody"><tr><td colspan="8" class="empty-msg">Loading&hellip;</td></tr></tbody>
      </table>
      <form id="cred-form" onsubmit="addCred(event)" style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <input class="scan-field" id="cred-user" placeholder="username" style="width:110px" required>
        <input class="scan-field" id="cred-secret" placeholder="password or hash" style="width:170px" required>
        <select class="scan-field" id="cred-type"><option value="password">password</option><option value="hash">hash</option></select>
        <input class="scan-field" id="cred-service" placeholder="service (smb/winrm/rdp...)" style="width:150px">
        <select class="scan-field" id="cred-status">
          <option value="untested">untested</option>
          <option value="valid">valid</option>
          <option value="valid-admin-uncertain">valid-admin? (unverified)</option>
          <option value="valid-admin">valid-admin</option>
          <option value="invalid">invalid</option>
        </select>
        <input class="scan-field" id="cred-notes" placeholder="notes" style="width:150px">
        <button type="submit" class="scan-field" style="background:var(--green);color:#0d1117;font-weight:700;cursor:pointer;border:none">Add</button>
      </form>
    </div>
  </div>
<div class="save-toast" id="toast">Saved</div>

  <div class="card">
    <div class="card-header"><h2>&#127919; Confirmed Access</h2></div>
    <div class="card-body">
      <p class="subtitle" style="margin:0 0 10px">Credentials sprayed from anywhere in this project that were confirmed to work against <em>this</em> host.</p>
      <table class="port-table" id="pwns-table">
        <thead><tr><th>User</th><th>Secret</th><th>Protocol</th><th>Mode</th><th>Result</th><th>Found On</th><th>Shares</th></tr></thead>
        <tbody id="pwns-tbody"><tr><td colspan="7" class="empty-msg">Loading&hellip;</td></tr></tbody>
      </table>
    </div>
  </div>"""

    # ── BloodHound card — only for hosts that look like a domain controller ──
    if is_dc:
        bloodhound_section = """
  <div class="card">
    <div class="card-header"><h2>&#128021; BloodHound</h2></div>
    <div class="card-body">
      <p class="subtitle" id="bloodhound-hint" style="margin:0 0 10px">Checking for valid LDAP credentials&hellip;</p>
      <form id="bloodhound-form" onsubmit="startBloodhound(event)" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <select class="scan-field" id="bloodhound-cred" style="min-width:220px" disabled>
          <option value="">No valid LDAP credentials yet</option>
        </select>
        <input class="scan-field" id="bloodhound-domain" placeholder="domain (e.g. THINC.LOCAL)" style="width:170px">
        <input class="scan-field" id="bloodhound-dc" placeholder="DC hostname (optional)" style="width:170px">
        <button type="submit" id="bloodhound-submit" class="scan-field" style="background:var(--green);color:#0d1117;font-weight:700;cursor:pointer;border:none" disabled>Start Scan</button>
      </form>
      <div id="bloodhound-progress" style="display:none;margin-top:10px">
        <div class="progress-label"><span id="bloodhound-progress-text"></span></div>
        <pre id="bloodhound-log" style="margin-top:6px;max-height:150px;overflow-y:auto;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:8px 10px;font-size:11px;color:var(--muted);white-space:pre-wrap"></pre>
      </div>
      <div class="section-toggle" onclick="document.getElementById('bloodhound-results-wrap').classList.toggle('section-collapsed')">
        <strong style="font-size:13px">Results</strong>
        <span id="bloodhound-result-count" style="color:var(--muted);font-size:12px"></span>
      </div>
      <div id="bloodhound-results-wrap">
        <p id="bloodhound-results-body" class="empty-msg" style="margin-top:8px">No scan run yet.</p>
      </div>
    </div>
  </div>"""
    else:
        bloodhound_section = ''

    # ── Inline JS (credentials CRUD + delete host) ───────────────────────────
    # Built as a plain string (not an f-string) so JS braces don't need escaping,
    # then the host value is safely embedded via json.dumps.
    script_js = """
<script>
const HOST = HOST_PLACEHOLDER;

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = (s === undefined || s === null) ? '' : s;
  return d.innerHTML;
}
function statusBadge(s) {
  if (s === 'valid-admin') return 'badge-red';
  if (s === 'valid-admin-uncertain') return 'badge-orange';
  if (s === 'valid') return 'badge-green';
  if (s === 'invalid') return 'badge-muted';
  return 'badge-orange';
}
function renderCreds(creds) {
  const tbody = document.getElementById('creds-tbody');
  if (!creds || !creds.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-msg">No credentials recorded yet.</td></tr>';
    return;
  }
  tbody.innerHTML = creds.map(c => `
    <tr>
      <td>${escapeHtml(c.username)}</td>
      <td><code>${escapeHtml(c.secret)}</code></td>
      <td>${escapeHtml(c.type)}</td>
      <td>${escapeHtml(c.service || '')}</td>
      <td><span class="badge ${statusBadge(c.status)}">${escapeHtml(c.status)}</span></td>
      <td>${escapeHtml(c.notes || '')}</td>
      <td><button class="scan-field" id="spray-btn-${c.id}" style="cursor:pointer;border:none;background:var(--cyan);color:#0d1117;font-weight:700" onclick="sprayThisCred('${c.id}', '${escapeHtml(c.username)}')">Spray</button></td>
      <td><button class="scan-field" style="cursor:pointer;border:none;background:var(--red);color:#fff" onclick="deleteCred('${c.id}')">&times;</button></td>
    </tr>`).join('');
}
function loadCreds() {
  fetch('/api/creds/' + encodeURIComponent(HOST))
    .then(r => { if (!r.ok) throw new Error('no server'); return r.json(); })
    .then(data => renderCreds(data.credentials))
    .catch(() => {
      document.getElementById('creds-tbody').innerHTML =
        '<tr><td colspan="7" class="empty-msg">Live dashboard required to manage credentials &mdash; run recon_server.py</td></tr>';
    });
}
function addCred(evt) {
  evt.preventDefault();
  const body = {
    username: document.getElementById('cred-user').value,
    secret: document.getElementById('cred-secret').value,
    type: document.getElementById('cred-type').value,
    service: document.getElementById('cred-service').value,
    status: document.getElementById('cred-status').value,
    notes: document.getElementById('cred-notes').value,
  };
  fetch('/api/creds/' + encodeURIComponent(HOST), {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)
  })
  .then(r => { if (!r.ok) throw new Error('save failed'); return r.json(); })
  .then(data => { renderCreds(data.credentials); document.getElementById('cred-form').reset(); if (typeof loadBloodhound === 'function') loadBloodhound(); })
  .catch(() => alert('Could not save credential — is recon_server.py running?'));
}
function deleteCred(id) {
  if (!confirm('Delete this credential?')) return;
  fetch('/api/creds/' + encodeURIComponent(HOST) + '/' + encodeURIComponent(id), { method: 'DELETE' })
    .then(r => { if (!r.ok) throw new Error('delete failed'); return r.json(); })
    .then(data => renderCreds(data.credentials))
    .catch(() => alert('Could not delete credential'));
}
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(showToast._h);
  showToast._h = setTimeout(() => t.classList.remove('show'), 1800);
}
let spraySilentPoll = false;
function sprayThisCred(credId, username) {
  const btn = document.getElementById('spray-btn-' + credId);
  fetch('/api/spray/' + encodeURIComponent(HOST) + '/' + encodeURIComponent(credId), { method: 'POST' })
    .then(r => { if (!r.ok) return r.json().then(d => { throw new Error(d.description || 'failed to start spray'); }); return r.json(); })
    .then(() => {
      if (btn) { btn.disabled = true; btn.textContent = '...'; }
      showToast('Spraying ' + username + ' against all hosts\u2026');
      spraySilentPoll = true;
      pollSpraySilently(credId, btn);
    })
    .catch(e => showToast('Could not start spray: ' + e.message));
}
function pollSpraySilently(credId, btn) {
  fetch('/api/spray/status').then(r => r.json()).then(s => {
    if (s.running) {
      setTimeout(() => pollSpraySilently(credId, btn), 1500);
    } else if (spraySilentPoll) {
      spraySilentPoll = false;
      if (btn) { btn.disabled = false; btn.textContent = 'Spray'; }
      showToast('Spray complete \u2014 ' + (s.hits ? s.hits.length : 0) + ' hit(s). Full results on the Credentials page.');
      loadCreds();
      loadPwns();
      if (typeof loadBloodhound === 'function') loadBloodhound();
    }
  }).catch(() => {
    spraySilentPoll = false;
    if (btn) { btn.disabled = false; btn.textContent = 'Spray'; }
  });
}
function deleteHost() {
  if (!confirm('Delete this host and ALL associated data (scan results, notes, credentials)? This cannot be undone.')) return;
  fetch('/api/host/' + encodeURIComponent(HOST), { method: 'DELETE' })
    .then(r => { if (!r.ok) throw new Error('delete failed'); return r.json(); })
    .then(() => { window.location.href = '../../index.html'; })
    .catch(() => alert('Could not delete host — is recon_server.py running?'));
}
function renderPwns(pwns) {
  const tbody = document.getElementById('pwns-tbody');
  if (!pwns || !pwns.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-msg">No confirmed access yet — spray a credential from the Credentials tab.</td></tr>';
    return;
  }
  tbody.innerHTML = pwns.map(p => `
    <tr>
      <td>${escapeHtml(p.username)}</td>
      <td><code>${escapeHtml(p.secret)}</code></td>
      <td>${escapeHtml(p.protocol)}</td>
      <td>${escapeHtml(p.mode)}</td>
      <td>${p.admin && p.admin_uncertain ? '<span class="badge badge-orange" title="Local account &#8212; UAC remote token filtering can make nxc report Pwn3d! even without genuine admin rights. Verify manually.">&#10067; admin? (unverified)</span>' : p.admin ? '<span class="badge badge-red">&#128128; admin</span>' : '<span class="badge badge-green">valid</span>'}</td>
      <td>${p.source_host === HOST ? '<em>this host</em>' : `<a href="../html/${escapeHtml(p.source_host.replace(/\\//g, '_').replace(/\\./g, '-'))}.html" style="color:var(--cyan)">${escapeHtml(p.source_host)}</a>`}</td>
      <td>${escapeHtml((p.shares || []).join(', ')) || '&mdash;'}</td>
    </tr>`).join('');
}
function loadPwns() {
  fetch('/api/pwns/' + encodeURIComponent(HOST))
    .then(r => { if (!r.ok) throw new Error('no server'); return r.json(); })
    .then(data => renderPwns(data.pwns))
    .catch(() => {
      document.getElementById('pwns-tbody').innerHTML =
        '<tr><td colspan="7" class="empty-msg">Live dashboard required &mdash; run recon_server.py</td></tr>';
    });
}
function escapeHtmlAttr(s) {
  return (s === undefined || s === null) ? '' : String(s).replace(/"/g, '&quot;');
}
loadCreds();
loadPwns();
BLOODHOUND_JS_PLACEHOLDER
FEROX_JS_PLACEHOLDER
</script>
"""
    script_js = script_js.replace('HOST_PLACEHOLDER', json.dumps(host)).replace(
        'FEROX_JS_PLACEHOLDER', ferox_js).replace('BLOODHOUND_JS_PLACEHOLDER', bloodhound_js)

    # ── Assemble page ─────────────────────────────────────────────────────────
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{h(host)} — ReconScan</title>
{CSS}
<style>
  /* The shared CSS above doesn't define these — they're needed to match
     the look of the dashboard's Scan Hosts box for the Feroxbuster/
     Credentials inputs on this page. */
  .scan-field {{ background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-family: var(--font-mono); padding: 6px 9px; font-size: 12px; }}
  .scan-field:focus {{ outline: none; border-color: var(--cyan); }}
  .scan-options {{ display: flex; gap: 16px; margin-top: 10px; flex-wrap: wrap; align-items: center; }}
  .scan-options label {{ font-size: 12px; color: var(--muted); display: flex; align-items: center; gap: 6px; }}
  .section-collapsed {{ display: none; }}
  .section-toggle {{ cursor: pointer; display: flex; align-items: center; gap: 8px; margin-top: 14px; user-select: none; }}
  .section-toggle:hover {{ color: var(--cyan); }}
</style>
</head>
<body>
<header>
  <span class="logo">[recon_scan]</span>
  <span style="color:var(--muted);font-family:var(--font-mono);font-size:13px">{h(host)}</span>
  <nav>
    <a href="../../index.html">&#8592; Index</a>
    <a href="../nmap/{h(safe)}.xml" target="_blank">tcp xml</a>
    <a href="../nmap/{h(safe)}_udp.xml" target="_blank">udp xml</a>
  </nav>
</header>
<div class="container">
  <h1>{h(host)}</h1>
  <p class="subtitle">{h(hostname) + ' &nbsp;&middot;&nbsp; ' if hostname else ''}{h(os_guess) + ' &nbsp;&middot;&nbsp; ' if os_guess else ''}Scanned {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
  {host_toolbar}

  <div class="stat-row">
    <div class="stat"><div class="val">{len(open_ports)}</div><div class="lbl">Open Ports</div></div>
    <div class="stat"><div class="val" style="color:var(--red)">{exploit_count}</div><div class="lbl">Exploit Hits</div></div>
  </div>

  <div class="card">
    <div class="card-header"><h2>&#128200; Scan Results</h2></div>
    <div class="card-body">{meta_html}{ports_html}</div>
  </div>

  <div class="card">
    <div class="card-header"><h2>&#128269; Searchsploit</h2>{exploit_badge}</div>
    <div class="card-body">{ss_html}</div>
  </div>
  {creds_section}
  {bloodhound_section}
  {ferox_section}
</div>
<footer>recon_scan.py &nbsp;&middot;&nbsp; Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
{script_js}
</body>
</html>"""

    html_path = out_dir / 'scans' / 'html' / f"{safe}.html"
    html_path.write_text(page, encoding='utf-8')
    return exploit_count, len(open_ports), hostname, os_guess

# ── Obsidian markdown notes ──────────────────────────────────────────────────
def render_obsidian_host(nm, host, safe, out_dir, exploit_count):
    """Generate a per-host Obsidian-compatible markdown note."""
    ss_path  = out_dir / 'scans' / 'searchsploit' / f"{safe}.txt"
    ss_groups, _ = parse_ss_hits(ss_path)

    host_data  = nm[host] if host in nm.all_hosts() else {}
    hostnames  = [e['name'] for e in host_data.get('hostnames', []) if e.get('name')]
    hostname   = hostnames[0] if hostnames else ''
    os_matches = host_data.get('osmatch', [])
    os_guess   = os_matches[0]['name'] if os_matches else ''
    os_acc     = os_matches[0].get('accuracy', '') if os_matches else ''

    # Collect open ports
    ports = []
    for proto in (host_data.all_protocols() if hasattr(host_data, 'all_protocols') else []):
        for port in sorted(host_data[proto].keys()):
            svc = host_data[proto][port]
            if svc.get('state') != 'open':
                continue
            ports.append({
                'port':    port,
                'proto':   proto,
                'name':    svc.get('name', ''),
                'product': svc.get('product', ''),
                'version': svc.get('version', ''),
                'extra':   svc.get('extrainfo', ''),
                'scripts': svc.get('script', {}),
            })

    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    tag_os = 'windows' if 'windows' in os_guess.lower() else ('linux' if 'linux' in os_guess.lower() else 'unknown-os')

    lines = []
    lines.append('---')
    lines.append(f'tags: [recon, sec200, {tag_os}]')
    lines.append(f'scan_date: {now}')
    lines.append(f'ip: {host}')
    if hostname:
        lines.append(f'hostname: {hostname}')
    if os_guess:
        lines.append(f'os: "{os_guess}"')
    lines.append(f'open_ports: {len(ports)}')
    lines.append(f'exploit_hits: {exploit_count}')
    lines.append('status: "[ ] untriaged"')
    lines.append('---')
    lines.append('')
    lines.append(f'# {host}')
    lines.append('')

    # Quick-reference box
    lines.append('## Overview')
    lines.append('')
    lines.append('| Field | Value |')
    lines.append('|-------|-------|')
    lines.append(f'| **IP** | `{host}` |')
    if hostname:
        lines.append(f'| **Hostname** | `{hostname}` |')
    if os_guess:
        lines.append(f'| **OS Guess** | {os_guess} ({os_acc}%) |')
    lines.append(f'| **Open Ports** | {len(ports)} |')
    lines.append(f'| **Exploit Hits** | {exploit_count} |')
    lines.append(f'| **Scanned** | {now} |')
    lines.append('')

    lines.append('## Timeline')
    lines.append('')
    lines.append('| Time | Event |')
    lines.append('|------|-------|')
    lines.append('| | Initial enumeration |')
    lines.append('| | Foothold obtained |')
    lines.append('| | Privilege escalation |')
    lines.append('| | Flag(s) captured |')
    lines.append('')

    # Ports table
    lines.append('## Open Ports')
    lines.append('')
    lines.append('| Port | Proto | Service | Version |')
    lines.append('|------|-------|---------|----------|')
    for p in ports:
        ver = ' '.join(filter(None, [p['product'], p['version'], p['extra']]))
        lines.append(f"| `{p['port']}` | {p['proto']} | {p['name'] or 'unknown'} | {ver or '—'} |")
    lines.append('')

    # Script output — collapsed callouts per port
    script_ports = [(p, p['scripts']) for p in ports if p['scripts']]
    if script_ports:
        lines.append('## NSE Script Output')
        lines.append('')
        for p, scripts in script_ports:
            lines.append(f"### Port {p['port']}/{p['proto']}")
            lines.append('')
            for scr_id, scr_out in scripts.items():
                if not scr_out.strip():
                    continue
                # Obsidian callout (collapsible)
                lines.append(f'> [!note]- {scr_id}')
                for scr_line in scr_out.strip().splitlines():
                    lines.append(f'> {scr_line}')
                lines.append('')

    # Searchsploit results
    lines.append('## Searchsploit Hits')
    lines.append('')
    if ss_groups:
        for query, entries in ss_groups.items():
            if not entries:
                continue
            lines.append(f'**Query:** `{query}`')
            lines.append('')
            lines.append('| EDB-ID | Type | Title | Path |')
            lines.append('|--------|------|-------|------|')
            for e in entries:
                label, _ = classify(e['title'])
                full_path = f"/usr/share/exploitdb/{e['path']}"
                lines.append(f"| EDB-{e['id']} | {label} | {e['title']} | `{full_path}` |")
            lines.append('')
    else:
        lines.append('*No searchsploit hits for this host.*')
        lines.append('')

    # ── System Information ────────────────────────────────────────────────────
    # IP/Hostname/OS-guess already live in Overview above — this section is
    # for details you fill in by hand once you have a shell, so it doesn't
    # repeat what the scan already told us.
    lines.append('## System Information')
    lines.append('')
    lines.append('| Field | Value |')
    lines.append('|-------|-------|')
    lines.append('| **OS (confirmed)** | |')
    lines.append('| **Architecture** | |')
    lines.append('| **Domain / Workgroup** | |')
    lines.append('| **Kernel / Build** | |')
    lines.append('| **Uptime** | |')
    lines.append('| **Current User** | |')
    lines.append('| **Privileges** | |')
    lines.append('| **AV / Defender** | |')
    lines.append('| **Language / Locale** | |')

    # Try to pre-fill domain from SMB script output
    for p in ports:
        for scr_id, scr_out in p['scripts'].items():
            if 'smb' in scr_id.lower() and scr_out:
                for scr_line in scr_out.splitlines():
                    if 'domain' in scr_line.lower() or 'workgroup' in scr_line.lower():
                        lines.append(f'> **SMB:** {scr_line.strip()}')
                        break
    lines.append('')

    # ── Network Information ───────────────────────────────────────────────────
    lines.append('## Network Information')
    lines.append('')
    lines.append('| Field | Value |')
    lines.append('|-------|-------|')

    # Pull MAC from scan if available
    mac = host_data.get('addresses', {}).get('mac', '')
    vendor = host_data.get('vendor', {}).get(mac, '') if mac else ''
    if mac:
        lines.append(f'| **MAC** | `{mac}`{f" ({vendor})" if vendor else ""} |')

    lines.append('| **Subnet** | |')
    lines.append('| **Gateway** | |')
    lines.append('| **DNS** | |')
    lines.append('| **Other Interfaces** | |')
    lines.append('| **Firewall / Filtering** | |')
    lines.append('')

    # ── Network Access (pivoting/tunneling) ────────────────────────────────────
    lines.append('## Network Access')
    lines.append('')
    lines.append('_How was this host reached? Leave as Direct if reachable straight '
                  'from the attack box. Fill in Pivot Tool/Via Host/Command(s) if '
                  'tunneling was required — this feeds the Pivoting subsection of '
                  'the final report._')
    lines.append('')
    lines.append('| Field | Value |')
    lines.append('|-------|-------|')
    lines.append('| **Access** | Direct |')
    lines.append('| **Pivot Tool** | |')
    lines.append('| **Pivot Via Host** | |')
    lines.append('')
    lines.append('**Tunnel command(s):**')
    lines.append('```')
    lines.append('')
    lines.append('```')
    lines.append('')

    # ── Attack Notes ──────────────────────────────────────────────────────────
    lines.append('## Attack Notes')
    lines.append('')

    # Auto-suggest vectors based on what's open
    lines.append('### Vectors to Investigate')
    lines.append('')
    port_names = {p['name'].lower() for p in ports if p['name']}
    port_nums  = {int(p['port']) for p in ports if str(p['port']).isdigit()}

    suggestions = []
    if 'ftp' in port_names:
        suggestions.append('FTP — check anonymous login, version exploits')
    if 'ssh' in port_names:
        suggestions.append('SSH — credential brute force, key auth, version exploits')
    if {80, 443, 8080, 8443} & port_nums:
        suggestions.append('HTTP/S — directory brute force (feroxbuster), vuln scan (nikto)')
    if {445, 139} & port_nums:
        suggestions.append('SMB — null/guest session, share enum (smbclient, netexec), version exploits')
    if 3389 in port_nums:
        suggestions.append('RDP — credential spray, BlueKeep/DejaBlue if unpatched')
    if {1433, 3306, 5432, 5984, 27017} & port_nums:
        suggestions.append('Database — check for default/weak credentials, unauthenticated access')
    if {161, 162} & port_nums:
        suggestions.append('SNMP — community string brute (onesixtyone), MIB walk (snmpwalk)')
    if 69 in port_nums:
        suggestions.append('TFTP — check for readable/writable files')
    if {88, 389, 636} & port_nums:
        suggestions.append('AD services — Kerberoasting, AS-REP roasting, BloodHound enum')
    if 25 in port_nums:
        suggestions.append('SMTP — user enumeration (VRFY/EXPN), open relay check')
    if 111 in port_nums or 2049 in port_nums:
        suggestions.append('NFS/RPC — check for exported shares (showmount -e)')
    if 623 in port_nums:
        suggestions.append('IPMI — default credentials (ADMIN/ADMIN), cipher 0 auth bypass')

    if suggestions:
        for s_ in suggestions:
            lines.append(f'- [ ] {s_}')
    else:
        lines.append('- [ ] ')
    lines.append('')

    lines.append('### Enumeration Commands')
    lines.append('')
    lines.append('```bash')
    lines.append(f'# Quick reference — adapt as needed')
    if {445, 139} & port_nums:
        lines.append(f'netexec smb {host} -u "" -p "" --shares')
        lines.append(f'netexec smb {host} -u "guest" -p "" --shares')
        lines.append(f'smbclient -L //{host} -N')
    if {80, 443, 8080} & port_nums:
        lines.append(f'feroxbuster -u http://{host} -w /usr/share/wordlists/dirb/common.txt')
        lines.append(f'nikto -h http://{host}')
    if {161} & port_nums:
        lines.append(f'onesixtyone -c /usr/share/doc/onesixtyone/dict.txt {host}')
        lines.append(f'snmpwalk -v2c -c public {host}')
    if 'ftp' in port_names:
        lines.append(f'ftp {host}  # try anonymous:anonymous')
    lines.append('```')
    lines.append('')
    
    lines.append('### Foothold')
    lines.append('')
    lines.append('**Vector:**')
    lines.append('')
    lines.append('```bash')
    lines.append('# command(s) used to get initial access')
    lines.append('```')
    lines.append('')
    lines.append('**Root cause:** _(one sentence — why this was exploitable, not just what you ran; this is what report grading actually checks for)_')
    lines.append('')
    lines.append('**Shell type:**')
    lines.append('- [ ] ssh/winrm')
    lines.append('- [ ] nc')
    lines.append('- [ ] mythic c2')
    lines.append('')
    
    lines.append('### Local Enumeration')
    lines.append('')
    lines.append('```bash')
    lines.append('# whoami && id')
    lines.append('# hostname')
    lines.append('# uname -a  /  systeminfo')
    lines.append('# ip a  /  ipconfig /all')
    lines.append('# cat /etc/passwd  /  net user')
    lines.append('# sudo -l  /  whoami /priv')
    lines.append('# find / -perm -4000 2>/dev/null  (SUID)')
    lines.append('# ps aux  /  tasklist')
    lines.append('```')
    lines.append('')

    lines.append('### Privilege Escalation')
    lines.append('')
    lines.append('**Vector:**')
    lines.append('')
    lines.append('```bash')
    lines.append('# privesc commands')
    lines.append('```')
    lines.append('')
    lines.append('**Root cause:** _(one sentence — the misconfiguration/vuln that made this possible)_')
    lines.append('')

    lines.append('### Post Exploitation')
    lines.append('')
    lines.append('```bash')
    lines.append('# hashdump / secretsdump')
    lines.append('# mimikatz')
    lines.append('# pivot setup')
    lines.append('```')
    lines.append('')

    lines.append('### Lateral Movement')
    lines.append('')
    lines.append('| Target | Method | Credentials Used |')
    lines.append('|--------|--------|------------------|')
    lines.append('| | | |')
    lines.append('')

    lines.append('### Credentials Found')
    lines.append('')
    lines.append('> Credentials for this host are tracked live on the dashboard '
                 '(Credentials card on this host\'s page) and pulled automatically '
                 'into the final report via `recon_report.py`. Use this space only '
                 'for narrative context (how a cred was found, reuse chains, etc.) — '
                 'not as the source of truth, so it never drifts out of sync with '
                 'what\'s actually recorded.')
    lines.append('')

    lines.append('### Loot')
    lines.append('')
    lines.append('| File / Secret | Location | Contents / Notes |')
    lines.append('|---------------|----------|------------------|')
    lines.append('| | | |')
    lines.append('')
    
    # ── Flags ────────────────────────────────────────────────────────────────
    lines.append('## Flags')
    lines.append('')
    lines.append('### User Flag')
    lines.append('')
    lines.append('**Path:** `C:\\Users\\<user>\\Desktop\\local.txt` / `/home/<user>/local.txt`')
    lines.append('')
    lines.append('```')
    lines.append('')
    lines.append('```')
    lines.append('')
    lines.append('**Proof screenshot:** (paste or embed)')
    lines.append('')
    lines.append('### Root / Admin Flag')
    lines.append('')
    lines.append('**Path:** `C:\\Users\\Administrator\\Desktop\\proof.txt` / `/root/proof.txt`')
    lines.append('')
    lines.append('```')
    lines.append('')
    lines.append('```')
    lines.append('')
    lines.append('**Proof screenshot:** (paste or embed)')
    lines.append('')
    lines.append('**Proof command output:**')
    lines.append('')
    lines.append('```')
    lines.append('# whoami && hostname && cat proof.txt')
    lines.append('# whoami && hostname && ipconfig /all')
    lines.append('```')
    lines.append('')

    md_path = out_dir / 'notes' / f"{host}.md"
    md_path.write_text('\n'.join(lines), encoding='utf-8')
    return md_path


def render_obsidian_summary(results, out_dir, scan_start):
    """Generate a scan summary index note that links to all host notes."""
    elapsed = str(datetime.now() - scan_start).split('.')[0]
    now     = datetime.now().strftime('%Y-%m-%d %H:%M')

    total_ports    = sum(r['ports']    for r in results)
    total_exploits = sum(r['exploits'] for r in results)
    hosts_with_hits = [r for r in results if r['exploits'] > 0]

    lines = []
    lines.append('---')
    lines.append('tags: [recon, sec200, scan-summary]')
    lines.append(f'scan_date: {now}')
    lines.append(f'hosts_scanned: {len(results)}')
    lines.append(f'total_open_ports: {total_ports}')
    lines.append(f'total_exploit_hits: {total_exploits}')
    lines.append('---')
    lines.append('')
    lines.append(f'# Scan Summary — {now}')
    lines.append('')
    lines.append('## Stats')
    lines.append('')
    lines.append('| | |')
    lines.append('|-|-|')
    lines.append(f'| **Hosts** | {len(results)} |')
    lines.append(f'| **Open Ports** | {total_ports} |')
    lines.append(f'| **Exploit Hits** | {total_exploits} |')
    lines.append(f'| **Duration** | {elapsed} |')
    lines.append('')

    # Hosts with exploit hits first
    if hosts_with_hits:
        lines.append('## ⚡ Hosts with Exploit Hits')
        lines.append('')
        for r in sorted(hosts_with_hits, key=lambda x: -x['exploits']):
            os_short = r['os'].split('(')[0].strip() if r['os'] else ''
            hn = f" · `{r['hostname']}`" if r['hostname'] else ''
            os_str = f" · {os_short}" if os_short else ''
            lines.append(f"- [[{r['host']}]]{hn}{os_str} — **{r['exploits']} hit(s)**")
        lines.append('')

    # All hosts table
    lines.append('## All Hosts')
    lines.append('')
    lines.append('| Host | Hostname | OS | Ports | Exploits | Services |')
    lines.append('|------|----------|-----|-------|----------|----------|')
    for r in results:
        os_short = r['os'].split('(')[0].strip() if r['os'] else '—'
        hn       = r['hostname'] or '—'
        svcs     = ', '.join(r['services'][:5]) if r['services'] else '—'
        hits     = f"**{r['exploits']}**" if r['exploits'] else '0'
        lines.append(f"| [[{r['host']}]] | {hn} | {os_short} | {r['ports']} | {hits} | {svcs} |")
    lines.append('')

    lines.append('## Attack Order')
    lines.append('')
    lines.append('> Prioritise hosts with exploit hits and exposed services.')
    lines.append('')
    for i, r in enumerate(sorted(results, key=lambda x: -x['exploits']), 1):
        lines.append(f'- [ ] {i}. [[{r['host']}]]')
    lines.append('')

    md_path = out_dir / 'notes' / '_scan_summary.md'
    md_path.write_text('\n'.join(lines), encoding='utf-8')
    ok(f"Obsidian notes: {out_dir}/notes/")
    return md_path


# ── Index page ────────────────────────────────────────────────────────────────
def render_index(results, out_dir, scan_start):
    total_hosts    = len(results)
    total_ports    = sum(r['ports'] for r in results)
    total_exploits = sum(r['exploits'] for r in results)
    local_count    = sum(1 for r in results if r.get('local'))
    proof_count    = sum(1 for r in results if r.get('proof'))

    cards = ''
    for r in results:
        safe = r['safe']
        ip   = r['host']
        local, proof = bool(r.get('local')), bool(r.get('proof'))
        exploit_badge = (
            f"<div class='exploit-count has-exploits'>&#9889; {r['exploits']} exploit hit(s)</div>"
            if r['exploits'] else
            "<div class='exploit-count no-exploits'>No exploit hits</div>"
        )
        meta_bits = [f"&#128299; {r['ports']} ports"]
        if r['hostname']:
            meta_bits.append(f"&#127991; {h(r['hostname'])}")
        if r['os']:
            meta_bits.append(f"&#128187; {h(r['os'].split('(')[0].strip())}")
        if r['services']:
            meta_bits.append(h(', '.join(r['services'][:6])))

        cards += f"""
<div class='target-card'>
  <a href='scans/html/{h(safe)}.html' style='text-decoration:none'>
    <div class='target-ip'>{h(ip)}</div>
    <div class='target-meta'>{'  '.join(f"<span>{b}</span>" for b in meta_bits)}</div>
    {exploit_badge}
  </a>
  {render_flag_chips(ip, local, proof, interactive=False)}
</div>"""

    elapsed = str(datetime.now() - scan_start).split('.')[0]

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconScan — Results</title>
{CSS}
</head>
<body>
<header>
  <span class="logo">[recon_scan]</span>
  <span style="color:var(--muted);font-size:13px">SEC200/OSCP Recon Results (static snapshot)</span>
  <nav><span style="color:var(--muted);font-size:12px;font-family:var(--font-mono)">{datetime.now().strftime('%Y-%m-%d %H:%M')}</span></nav>
</header>
<div class="container">
  <h1>Scan Results</h1>
  <p class="subtitle">Completed in {h(elapsed)} &nbsp;&middot;&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    &nbsp;&middot;&nbsp; Local/Proof are read-only here — run <code>recon_server.py {h(str(out_dir))}</code> for the live dashboard to check them off.</p>
  <div class="stat-row">
    <div class="stat"><div class="val">{total_hosts}</div><div class="lbl">Hosts</div></div>
    <div class="stat"><div class="val">{total_ports}</div><div class="lbl">Open Ports</div></div>
    <div class="stat"><div class="val" style="color:var(--red)">{total_exploits}</div><div class="lbl">Exploit Hits</div></div>
    <div class="stat"><div class="val" style="color:var(--green)">{local_count}/{total_hosts}</div><div class="lbl">Local</div></div>
    <div class="stat"><div class="val" style="color:var(--purple)">{proof_count}/{total_hosts}</div><div class="lbl">Proof</div></div>
  </div>
  <input class="search-bar" id="search" type="text" placeholder="Filter by IP, hostname, or service..." oninput="filterCards()">
  <div class="grid" id="grid">{cards}</div>
</div>
<footer>recon_scan.py &nbsp;&middot;&nbsp; Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
<script>
function filterCards() {{
  const q = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('#grid > .target-card').forEach(c => {{
    c.classList.toggle('hidden', !c.textContent.toLowerCase().includes(q));
  }});
}}
</script>
</body>
</html>"""

    (out_dir / 'index.html').write_text(page, encoding='utf-8')
    ok(f"Index: {out_dir}/index.html")

# ── Worker ────────────────────────────────────────────────────────────────────
def process_target(args_tuple):
    target, out_dir, port_args, do_udp, proxy_port = args_tuple
    safe = target.replace('/', '_').replace('.', '-')

    nm, safe = scan_target(target, out_dir, port_args, do_udp=do_udp, proxy_port=proxy_port)
    if nm is None:
        return {
            'host': target, 'safe': safe,
            'ports': 0, 'exploits': 0,
            'hostname': '', 'os': '', 'services': [],
            'scanned_at': datetime.now().strftime('%Y-%m-%d %H:%M')
        }

    exploit_count = run_searchsploit(nm, target, safe, out_dir)
    exploit_count, port_count, hostname, os_guess = render_target_html(nm, target, safe, out_dir)

    # Top services for index card
    services = []
    if target in nm.all_hosts():
        for proto in nm[target].all_protocols():
            for port in nm[target][proto]:
                svc = nm[target][proto][port]
                name = svc.get('name', '')
                if name and name not in services:
                    services.append(name)

    # Notes are hand-edited during the engagement (creds, loot, foothold, etc.)
    # — never clobber an existing note on a rescan, only create it if missing.
    notes_path = out_dir / 'notes' / f"{target}.md"
    if notes_path.exists():
        warn(f"Notes exist for {target} — leaving as-is (rescan updates html/searchsploit only)")
    else:
        render_obsidian_host(nm, target, safe, out_dir, exploit_count)

    ok(f"Report: scans/html/{safe}.html")
    return {
        'host': target, 'safe': safe,
        'ports': port_count, 'exploits': exploit_count,
        'hostname': hostname, 'os': os_guess, 'services': services,
        'scanned_at': datetime.now().strftime('%Y-%m-%d %H:%M')
    }

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)
    args = parse_args()
    targets, out_dir = preflight(args)
    scan_start = datetime.now()

    existing = load_manifest(out_dir)
    if existing:
        ok(f"{len(existing)} host(s) already in project — results will be merged, not replaced")

    print()
    log(f"Starting scans with {args.threads} parallel threads...")
    if not args.no_udp:
        log(f"UDP scan enabled — {len(UDP_PORTS)} high-value ports per host")
    else:
        warn("UDP scan disabled (--no-udp)")
    print()

    do_udp = not args.no_udp
    work = [(t, out_dir, args.ports, do_udp, args.proxy_port) for t in targets]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(process_target, w): w[0] for w in work}
        for fut in concurrent.futures.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                warn(f"Error processing {futures[fut]}: {e}")

    # Merge this run's results into whatever was already in the project.
    # Rescanned hosts get fresh scan data; Local/Proof flags (set from the
    # dashboard) are preserved regardless of rescans.
    merged = merge_scan_results(existing, results)
    all_results = sorted(merged.values(), key=lambda r: r['host'])

    print()
    render_index(all_results, out_dir, scan_start)
    render_obsidian_summary(all_results, out_dir, scan_start)
    save_manifest(out_dir, merged)
    write_targets_file(out_dir, merged)
    write_creds_files(out_dir, merged)
    chown_project_dir(out_dir)
    print()
    print(f"{B}{G}Done.{X} Open: {C}{out_dir}/index.html{X}")
    print(f"     Notes: {C}{out_dir}/notes/_scan_summary.md{X}")
    print(f"     Re-run with the same project name ({C}{out_dir}{X}) any time to add more hosts.")
    print(f"     Live dashboard: {C}python3 recon_server.py {out_dir}{X}")
    print()

if __name__ == '__main__':
    main()
