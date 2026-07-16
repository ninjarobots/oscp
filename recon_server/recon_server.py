#!/usr/bin/env python3
"""
recon_server.py — live dashboard + scan launcher for a recon_scan.py project.
Usage: sudo python3 recon_server.py <project_dir> [--host 127.0.0.1] [--port 5000]

The full workflow now lives in the app: paste targets into the dashboard,
hit Start Scan, and hosts populate the list as each one finishes — no need
to run recon_scan.py from the CLI first (though you still can, e.g. for
scripted/headless runs against the same project).

Root/sudo is needed for the same reason recon_scan.py needed it: nmap's
-sS/-sU scans require raw sockets. Run this as root, or set up passwordless
sudo for nmap, or scans kicked off from the dashboard will fail.

Keep recon_common.py AND recon_scan.py in the same directory as this file —
scanning re-uses recon_scan.py's scan/report/notes-generation code directly.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from datetime import datetime
from pathlib import Path

try:
    from flask import Flask, jsonify, request, send_from_directory, send_file, abort
except ImportError:
    print("[-] Flask not found. Install with: pip install flask --break-system-packages")
    sys.exit(1)

try:
    from recon_common import (
        h, load_manifest, save_manifest, manifest_path, ensure_project_dirs,
        merge_scan_results, write_creds_files, write_targets_file, append_cred_to_note, render_flag_chips,
        chown_project_dir, parse_domain_from_note, nmap_needs_sudo, CSS, log, ok, warn, err, C, G, X, B,
    )
except ImportError:
    print("[-] recon_common.py not found. Keep it in the same directory as recon_server.py")
    sys.exit(1)

try:
    import recon_scan as rs  # reuses scan_target/process_target/render_* — no logic duplicated
except ImportError as e:
    print(f"[-] Could not import recon_scan.py ({e}). Keep it in the same directory as recon_server.py")
    sys.exit(1)

try:
    import recon_report_docx
except ImportError as e:
    recon_report_docx = None
    print(f"[!] recon_report_docx.py not available ({e}) — the Generate Report button will be disabled. "
          f"Install with: pip install python-docx --break-system-packages")

try:
    import recon_remap as rr
except ImportError as e:
    print(f"[-] Could not import recon_remap.py ({e}). Keep it in the same directory as recon_server.py")
    sys.exit(1)

app = Flask(__name__)
PROJECT_DIR = None
PROXY_PORT = 9050  # overridable via --proxy-port; used for proxychains-fallback scans
BLOODHOUND_CE = None  # dict {host, token_id, token_key} if --bh-host/--bh-key-id/--bh-key were all provided, else None
MANIFEST_LOCK = threading.Lock()

SCAN_STATE = {
    'running': False, 'total': 0, 'done': 0, 'remaining': [], 'log': [],
    'started_at': None, 'finished_at': None, 'error': None,
}
STATE_LOCK = threading.Lock()

# ── Credential spray ────────────────────────────────────────────────────────
# Same protocol logic as spray-all.sh: local-auth-capable protocols get both
# a --local-auth and a domain pass; a detected hash restricts the run to
# protocols that actually understand -H (NTLM/Kerberos-based auth only).
SPRAY_ALL_PROTOCOLS = ['winrm', 'wmi', 'smb', 'nfs', 'ldap', 'ssh', 'rdp', 'mssql', 'vnc', 'ftp']
SPRAY_LOCAL_AUTH_PROTOCOLS = ['winrm', 'wmi', 'smb', 'rdp', 'mssql']
SPRAY_HASH_CAPABLE_PROTOCOLS = ['smb', 'winrm', 'wmi', 'mssql', 'rdp', 'ldap']
SPRAY_HASH_RE = re.compile(r'^[0-9a-fA-F]{32}(:[0-9a-fA-F]{32})?$')
SPRAY_TIMEOUT = 20

SPRAY_STATE = {
    'running': False, 'total': 0, 'done': 0, 'log': [], 'hits': [],
    'label': None, 'started_at': None, 'finished_at': None, 'error': None,
}
SPRAY_STATE_LOCK = threading.Lock()

# ── Feroxbuster ──────────────────────────────────────────────────────────────
FEROX_STATE = {
    'running': False, 'host': None, 'url': None, 'log': [], 'hits': [],
    'started_at': None, 'finished_at': None, 'error': None,
}
FEROX_STATE_LOCK = threading.Lock()
FEROX_DEFAULT_WORDLIST = '/usr/share/wordlists/dirb/common.txt'

# ── BloodHound ───────────────────────────────────────────────────────────────
BLOODHOUND_STATE = {
    'running': False, 'host': None, 'log': [],
    'started_at': None, 'finished_at': None, 'error': None,
}
BLOODHOUND_STATE_LOCK = threading.Lock()
BLOODHOUND_VALID_STATUSES = {'valid', 'valid-admin', 'valid-admin-uncertain'}


def find_ldap_credentials(manifest, target_host):
    """Every credential anywhere in the project that's confirmed to work
    over LDAP against target_host — either via a spray hit (protocol=ldap,
    target=target_host) or a manually-set 'ldap' service + valid status on
    its own host record. Best (valid-admin) first."""
    status_rank = {'valid-admin': 0, 'valid-admin-uncertain': 1, 'valid': 2}
    found = []
    for source_host, r in manifest.items():
        for c in r.get('credentials', []):
            has_spray_hit = any(
                h.get('target') == target_host and h.get('protocol') == 'ldap'
                for h in c.get('spray_results', [])
            )
            manual_match = (
                'ldap' in (c.get('service') or '').lower()
                and c.get('status') in BLOODHOUND_VALID_STATUSES
                and source_host == target_host
            )
            if has_spray_hit or manual_match:
                found.append({
                    'source_host': source_host, 'cred_id': c['id'],
                    'username': c.get('username', ''), 'secret': c.get('secret', ''),
                    'type': c.get('type', 'password'), 'status': c.get('status', 'untested'),
                })
    found.sort(key=lambda c: status_rank.get(c['status'], 3))
    return found


def manifest_mtime():
    mpath = manifest_path(PROJECT_DIR)
    return mpath.stat().st_mtime if mpath.exists() else 0


# ── Background scan job ────────────────────────────────────────────────────────
def run_scan_job(targets, threads, port_args, do_udp, proxy_port):
    with STATE_LOCK:
        SCAN_STATE.update(
            running=True, total=len(targets), done=0, remaining=list(targets),
            log=[f"Starting scan of {len(targets)} host(s) — {threads} thread(s), ports: {port_args}"],
            started_at=datetime.now().isoformat(), finished_at=None, error=None,
        )
    scan_start = datetime.now()
    try:
        work = [(t, PROJECT_DIR, port_args, do_udp, proxy_port) for t in targets]
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(rs.process_target, w): w[0] for w in work}
            for fut in concurrent.futures.as_completed(futures):
                host = futures[fut]
                try:
                    result = fut.result()
                except Exception as e:
                    safe = host.replace('/', '_').replace('.', '-')
                    result = {
                        'host': host, 'safe': safe, 'ports': 0, 'exploits': 0,
                        'hostname': '', 'os': '', 'services': [],
                        'scanned_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                    }
                    with STATE_LOCK:
                        SCAN_STATE['log'].append(f"[!] {host}: error — {e}")

                # Merge this one host in immediately so the dashboard can show
                # it as soon as it's done, without waiting for the whole batch.
                with MANIFEST_LOCK:
                    manifest = load_manifest(PROJECT_DIR)
                    manifest = merge_scan_results(manifest, [result])
                    save_manifest(PROJECT_DIR, manifest)

                with STATE_LOCK:
                    SCAN_STATE['done'] += 1
                    if host in SCAN_STATE['remaining']:
                        SCAN_STATE['remaining'].remove(host)
                    SCAN_STATE['log'].append(
                        f"[+] {host}: {result.get('ports', 0)} port(s), "
                        f"{result.get('exploits', 0)} exploit hit(s)"
                    )

        # Refresh the static snapshot + notes summary once the batch is done.
        with MANIFEST_LOCK:
            manifest = load_manifest(PROJECT_DIR)
        all_results = sorted(manifest.values(), key=lambda r: r['host'])
        rs.render_index(all_results, PROJECT_DIR, scan_start)
        rs.render_obsidian_summary(all_results, PROJECT_DIR, scan_start)
        write_targets_file(PROJECT_DIR, manifest)
        write_creds_files(PROJECT_DIR, manifest)
        with STATE_LOCK:
            SCAN_STATE['log'].append("Scan complete.")
    except Exception as e:
        with STATE_LOCK:
            SCAN_STATE['error'] = str(e)
            SCAN_STATE['log'].append(f"[-] Scan job failed: {e}")
    finally:
        chown_project_dir(PROJECT_DIR)
        with STATE_LOCK:
            SCAN_STATE['running'] = False
            SCAN_STATE['finished_at'] = datetime.now().isoformat()


# ── Background spray job ────────────────────────────────────────────────────
def _run_one_nxc(protocol, target, user, secret, hash_mode, local_auth, smb_shares):
    cmd = ['nxc', protocol, target, '-u', user, '-H' if hash_mode else '-p', secret]
    if local_auth:
        cmd.append('--local-auth')
    if smb_shares:
        cmd.append('--shares')
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SPRAY_TIMEOUT)
        return proc.stdout
    except Exception:
        return ''


def _parse_spray_output(output, protocol, target, mode):
    """Pull [+]/Pwn3d hit lines and (for smb) READ/WRITE share lines out of
    raw nxc output, same signal spray-all.sh's grep filters for.

    'Pwn3d!' is nxc's own signal that it actually attempted (and
    succeeded at) code execution — but for LOCAL (non-domain, non-RID-500)
    admin accounts, Windows applies UAC remote token filtering
    (LocalAccountTokenFilterPolicy) by default, which silently strips
    admin rights from the token used for network connections even though
    the account genuinely is in the local Administrators group. This is a
    well-documented source of Pwn3d false positives specifically for
    local-account checks — domain accounts aren't subject to it. We can't
    fix nxc's own detection, but we can flag which admin hits came from a
    `--local-auth` check so they get a second look instead of blind trust."""
    hits, shares = [], []
    for line in output.splitlines():
        clean = re.sub(r'\x1b\[[0-9;]*m', '', line).strip()
        if not clean:
            continue
        if '[+]' in clean or 'Pwn3d' in clean:
            is_admin = 'Pwn3d' in clean
            hits.append({
                'target': target, 'protocol': protocol, 'mode': mode,
                'admin': is_admin, 'admin_uncertain': is_admin and mode == 'local',
                'raw': clean,
            })
        elif protocol == 'smb' and ('READ' in clean or 'WRITE' in clean):
            shares.append(clean)
    return hits, shares


def run_spray_job(spray_targets, label):
    """
    spray_targets: list of {source_host, cred_id, username, secret} dicts —
    one entry for a single-credential spray, every stored credential for a
    "spray all" run. Hash-vs-password is detected per credential, since a
    spray-all run can easily mix both in the same batch.
    """
    with SPRAY_STATE_LOCK:
        SPRAY_STATE.update(
            running=True, total=0, done=0, hits=[], label=label,
            log=[f"Spraying {label} against all known hosts in the project..."],
            started_at=datetime.now().isoformat(), finished_at=None, error=None,
        )
    try:
        with MANIFEST_LOCK:
            manifest = load_manifest(PROJECT_DIR)
        targets = sorted(manifest.keys())
        if not targets or not spray_targets:
            with SPRAY_STATE_LOCK:
                SPRAY_STATE['log'].append("Nothing to spray — no hosts and/or no credentials in this project.")
            return

        # Build the full (cred, target, protocol, mode) job list up front,
        # detecting hash-vs-password per credential rather than once for the
        # whole run, so a spray-all batch can freely mix hashes and passwords.
        jobs = []
        for cred in spray_targets:
            hash_mode = bool(SPRAY_HASH_RE.match(cred['secret']))
            cred['_hash_mode'] = hash_mode
            protocols = SPRAY_HASH_CAPABLE_PROTOCOLS if hash_mode else SPRAY_ALL_PROTOCOLS
            local_auth_protocols = [p for p in SPRAY_LOCAL_AUTH_PROTOCOLS if p in protocols]
            if hash_mode:
                skipped = [p for p in SPRAY_ALL_PROTOCOLS if p not in protocols]
                with SPRAY_STATE_LOCK:
                    SPRAY_STATE['log'].append(
                        f"'{cred['username']}': hash detected — skipping protocols that don't support -H: {', '.join(skipped)}"
                    )
            for target in targets:
                for protocol in protocols:
                    if protocol in local_auth_protocols:
                        jobs.append((cred, target, protocol, 'local'))
                    jobs.append((cred, target, protocol, 'domain'))

        with SPRAY_STATE_LOCK:
            SPRAY_STATE['total'] = len(jobs)

        # Per-nxc-call timeout stays fixed (SPRAY_TIMEOUT) regardless of job
        # count — that's "how long to wait for one network response," which
        # has nothing to do with how many creds are in the batch. What
        # actually needs to scale with a bigger batch is concurrency, so
        # total wall-clock time doesn't blow up as more creds get added.
        max_workers = min(40, max(15, len(jobs) // 20))

        results_by_cred = {}          # (source_host, cred_id) -> [hit, ...]
        shares_by_cred_target = {}    # (source_host, cred_id, target) -> [share line, ...]

        def do_job(job):
            cred, target, protocol, mode = job
            output = _run_one_nxc(
                protocol, target, cred['username'], cred['secret'],
                hash_mode=cred['_hash_mode'], local_auth=(mode == 'local'), smb_shares=(protocol == 'smb'),
            )
            hits, shares = _parse_spray_output(output, protocol, target, mode)
            return cred, target, protocol, mode, hits, shares

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(do_job, j) for j in jobs]
            for fut in concurrent.futures.as_completed(futures):
                cred, target, protocol, mode, hits, shares = fut.result()
                key = (cred['source_host'], cred['cred_id'])
                if hits:
                    results_by_cred.setdefault(key, []).extend(hits)
                    with SPRAY_STATE_LOCK:
                        for hit in hits:
                            if hit['admin'] and hit.get('admin_uncertain'):
                                tag = 'ADMIN? (local acct — UAC may filter, verify manually)'
                            elif hit['admin']:
                                tag = 'ADMIN'
                            else:
                                tag = 'valid'
                            SPRAY_STATE['log'].append(
                                f"[+] {tag}: {cred['username']} @ {target} ({protocol}) — {hit['raw']}"
                            )
                if shares:
                    shares_by_cred_target.setdefault(key + (target,), []).extend(shares)
                with SPRAY_STATE_LOCK:
                    SPRAY_STATE['done'] += 1

        for key, hits in results_by_cred.items():
            for hit in hits:
                if hit['protocol'] == 'smb':
                    skey = key + (hit['target'],)
                    if skey in shares_by_cred_target:
                        hit['shares'] = list(dict.fromkeys(shares_by_cred_target[skey]))  # dedupe, preserve order

        all_hits_flat = [hit for hits in results_by_cred.values() for hit in hits]
        with SPRAY_STATE_LOCK:
            SPRAY_STATE['hits'] = all_hits_flat
            SPRAY_STATE['log'].append(
                f"Spray complete — {len(all_hits_flat)} hit(s) across {len(targets)} host(s) "
                f"and {len(spray_targets)} credential(s)."
            )

        # Persist results back onto each credential — including a "sprayed,
        # zero hits" stamp for creds that were tried but found nothing, so
        # the UI can tell "not sprayed yet" apart from "sprayed, no luck."
        with MANIFEST_LOCK:
            manifest = load_manifest(PROJECT_DIR)
            for cred in spray_targets:
                key = (cred['source_host'], cred['cred_id'])
                hits = results_by_cred.get(key, [])
                host_rec = manifest.get(cred['source_host'])
                if not host_rec:
                    continue
                for c in host_rec.get('credentials', []):
                    if c.get('id') == cred['cred_id']:
                        c['spray_results'] = hits
                        c['last_sprayed_at'] = datetime.now().isoformat()
                        # Spray always tests every currently-known host across
                        # every supported protocol, so zero hits is a real,
                        # meaningful result — not "not yet tried" — and
                        # leaving it stuck at "untested" forever makes it
                        # indistinguishable from a credential nobody has ever
                        # sprayed. Only auto-set for creds still sitting at
                        # the default, though: never downgrade a status that
                        # was already confirmed valid (by an earlier spray or
                        # by hand) just because this one run came back empty
                        # — that could just be a host being temporarily down.
                        if hits:
                            confident_admin = any(hit.get('admin') and not hit.get('admin_uncertain') for hit in hits)
                            any_admin = any(hit.get('admin') for hit in hits)
                            if confident_admin:
                                c['status'] = 'valid-admin'
                            elif any_admin:
                                c['status'] = 'valid-admin-uncertain'
                            else:
                                c['status'] = 'valid'
                        elif c.get('status') == 'untested':
                            c['status'] = 'invalid'
                        break
            save_manifest(PROJECT_DIR, manifest)
    except Exception as e:
        with SPRAY_STATE_LOCK:
            SPRAY_STATE['error'] = str(e)
            SPRAY_STATE['log'].append(f"[-] Spray job failed: {e}")
    finally:
        chown_project_dir(PROJECT_DIR)
        with SPRAY_STATE_LOCK:
            SPRAY_STATE['running'] = False
            SPRAY_STATE['finished_at'] = datetime.now().isoformat()


# ── Background feroxbuster job ────────────────────────────────────────────────
def _is_interesting_ferox_status(status) -> bool:
    """2xx/3xx plus 401 — see _consume_new_ferox_lines for the reasoning
    (403 excluded: too often a blanket WAF/deny rule rather than a real
    signal). Shared between ingest-time filtering (new scans) and
    display-time filtering (GET /api/ferox/<host>), so results from a scan
    that ran before this filter existed/changed don't linger unfiltered
    forever — they get cleaned up on the next view, not just the next scan."""
    return isinstance(status, int) and (200 <= status < 400 or status == 401)


def _consume_new_ferox_lines(path, offset, hits_accum, status_filter=True):
    """Reads any new *complete* lines appended to path since byte offset,
    parses 'response'-type JSON entries into hits_accum. Returns
    (new_offset, newly_added_hits). Incomplete trailing lines (still being
    written) are left for the next call rather than parsed early.

    By default only keeps 2xx/3xx plus 401 — a wordlist scan's raw output
    is overwhelmingly 404s (most guesses don't exist, which is normal),
    which is noise for the dashboard even though it's harmless in the raw
    file. 403 is excluded from the default too — in practice a lot of
    targets return a blanket 403 (WAF, default-deny rule, etc.) across
    dozens of paths, which is exactly the kind of noise this filter is
    meant to cut. 401 (Unauthorized) tends to be a cleaner signal — it
    usually means a specific auth-gated resource, not a blanket rule — so
    it stays in by default. The full untouched output always stays on
    disk at `path` regardless of this filter — nothing is lost, only what
    gets surfaced to the UI/manifest is curated. Uncheck the status filter
    entirely to see 403s (and 404s) if you want them."""
    new_hits = []
    if not path.exists():
        return offset, new_hits
    with open(path, 'rb') as f:
        f.seek(offset)
        chunk = f.read()
    if not chunk:
        return offset, new_hits
    last_nl = chunk.rfind(b'\n')
    if last_nl == -1:
        return offset, new_hits  # nothing complete yet
    complete, new_offset = chunk[:last_nl + 1], offset + last_nl + 1
    for raw_line in complete.split(b'\n'):
        line = raw_line.decode('utf-8', errors='ignore').strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get('type') != 'response':
            continue
        status = obj.get('status')
        is_interesting = _is_interesting_ferox_status(status)
        if status_filter and not is_interesting:
            continue
        hit = {
            'url': obj.get('url', ''),
            'status': status,
            'length': obj.get('content_length'),
            'words': obj.get('word_count'),
            'lines': obj.get('line_count'),
        }
        hits_accum.append(hit)
        new_hits.append(hit)
    return new_offset, new_hits


def run_ferox_job(host, safe, url, wordlist, extensions, threads, dont_filter=True, status_filter=True):
    out_dir = PROJECT_DIR / 'scans' / 'ferox'
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{safe}.jsonl"
    # Start each run with a clean file — otherwise a prior run's lines would
    # get re-parsed as if they were new hits from this run.
    try:
        out_path.unlink()
    except FileNotFoundError:
        pass

    with FEROX_STATE_LOCK:
        FEROX_STATE.update(
            running=True, host=host, url=url, log=[f"Starting feroxbuster against {url}"],
            hits=[], started_at=datetime.now().isoformat(), finished_at=None, error=None,
        )

    # -D/--dont-filter disables feroxbuster's automatic wildcard/soft-404
    # detection, which is ON by default and will silently drop real 200/300
    # hits whenever their response size happens to match its baseline probe
    # — this is by far the most common reason "it ran but found nothing"
    # even though something is genuinely there. Default to disabling it;
    # only re-enable (dont_filter=False) if the target has a true wildcard
    # vhost/catch-all and you specifically want that noise suppressed.
    # -k/--insecure disables TLS cert validation — OSCP/PEN-200 lab hosts
    # nearly always run self-signed certs, and feroxbuster otherwise
    # outright refuses to connect on https targets ("certificate verify
    # failed"). Always on; there's no legitimate lab scenario where you'd
    # want the scan to fail instead of just ignoring the cert.
    cmd = ['feroxbuster', '-u', url, '-w', wordlist, '--json', '-q', '-k', '-o', str(out_path)]
    if dont_filter:
        cmd += ['-D']
    if extensions:
        cmd += ['-x', extensions]
    if threads:
        cmd += ['-t', str(threads)]

    hits = []
    try:
        # IMPORTANT: -o redirects feroxbuster's result output to the file
        # instead of stdout ("Output file to write results to (default:
        # stdout)" — passing -o means stdout gets essentially nothing with
        # -q set). Results only ever land in the file, so we tail *that*
        # for both live progress and the final hit list, rather than
        # reading a stdout stream that -o has redirected away from.
        # stdout/stderr are captured only for error visibility (e.g. a bad
        # wordlist path) — read once at the end, not depended on for hits.
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

        offset = 0
        while proc.poll() is None:
            time.sleep(1)
            offset, new_hits = _consume_new_ferox_lines(out_path, offset, hits, status_filter)
            if new_hits:
                with FEROX_STATE_LOCK:
                    FEROX_STATE['hits'] = list(hits)
                    for hit in new_hits:
                        FEROX_STATE['log'].append(f"[{hit['status']}] {hit['url']} ({hit['length']} bytes)")

        # Final pass — catches whatever was written between the last poll
        # and the process actually exiting.
        offset, new_hits = _consume_new_ferox_lines(out_path, offset, hits, status_filter)
        if new_hits:
            with FEROX_STATE_LOCK:
                FEROX_STATE['hits'] = list(hits)
                for hit in new_hits:
                    FEROX_STATE['log'].append(f"[{hit['status']}] {hit['url']} ({hit['length']} bytes)")

        if proc.returncode not in (0, None):
            stderr_output = (proc.stderr.read() if proc.stderr else '').strip()
            with FEROX_STATE_LOCK:
                FEROX_STATE['log'].append(f"[!] feroxbuster exited with code {proc.returncode}")
                if stderr_output:
                    FEROX_STATE['log'].append(stderr_output[-500:])

        with FEROX_STATE_LOCK:
            FEROX_STATE['log'].append(f"Feroxbuster complete: {len(hits)} result(s).")

        with MANIFEST_LOCK:
            manifest = load_manifest(PROJECT_DIR)
            if host in manifest:
                manifest[host]['ferox'] = hits
                manifest[host]['ferox_target_url'] = url
                manifest[host]['ferox_scanned_at'] = datetime.now().isoformat()
                save_manifest(PROJECT_DIR, manifest)
    except FileNotFoundError:
        with FEROX_STATE_LOCK:
            FEROX_STATE['error'] = 'feroxbuster not found on this server'
            FEROX_STATE['log'].append('[-] feroxbuster not found on this server')
    except Exception as e:
        with FEROX_STATE_LOCK:
            FEROX_STATE['error'] = str(e)
            FEROX_STATE['log'].append(f"[-] Feroxbuster job failed: {e}")
    finally:
        chown_project_dir(PROJECT_DIR)
        with FEROX_STATE_LOCK:
            FEROX_STATE['running'] = False
            FEROX_STATE['finished_at'] = datetime.now().isoformat()


# ── Background BloodHound job ───────────────────────────────────────────────
def _bloodhound_ce_signed_request(method, uri, body=None, content_type=None, timeout=30):
    """
    BloodHound CE's HMAC signed-request scheme, implemented to match
    SpecterOps' own reference client (apiclient.py) exactly: a 3-link
    HMAC-SHA256 chain over (1) the method+URI, (2) the request hour, then
    (3) the request body. Returns (status_code, response_bytes). Raises
    urllib.error.HTTPError / OSError on failure — caller catches these.
    """
    token_id = BLOODHOUND_CE['token_id']
    token_key = BLOODHOUND_CE['token_key']
    base = BLOODHOUND_CE['host']

    digester = hmac.new(token_key.encode(), None, hashlib.sha256)
    digester.update((method + uri).encode())
    digester = hmac.new(digester.digest(), None, hashlib.sha256)

    # Truncated to the hour, matching the reference implementation — this
    # limits replay-ability without requiring clock-perfect sync.
    request_datetime = datetime.now().astimezone().isoformat('T')
    digester.update(request_datetime[:13].encode())
    digester = hmac.new(digester.digest(), None, hashlib.sha256)

    if body is not None:
        digester.update(body)

    signature = base64.b64encode(digester.digest()).decode()
    headers = {
        'User-Agent': 'reconscan-bloodhound-submit',
        'Authorization': f'bhesignature {token_id}',
        'RequestDate': request_datetime,
        'Signature': signature,
    }
    if content_type:
        headers['Content-Type'] = content_type

    req = urllib.request.Request(base + uri, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


def submit_to_bloodhound_ce(zip_bytes):
    """
    Uploads a completed collection zip to a running BloodHound CE instance:
    start a file-upload job, upload the zip, close the job to queue
    ingestion. Best-effort only — the local zip is always saved regardless
    of whether this succeeds, so a failure here never loses data, just
    means you upload it manually instead. Returns (ok, message).
    """
    if not BLOODHOUND_CE:
        return False, "BloodHound CE not configured (--bh-host/--bh-key-id/--bh-key not set)"
    try:
        status, resp_body = _bloodhound_ce_signed_request('POST', '/api/v2/file-upload/start')
        if status not in (200, 201):
            return False, f"start job failed: HTTP {status}"
        job_id = json.loads(resp_body)['data']['id']

        status, _ = _bloodhound_ce_signed_request(
            'POST', f'/api/v2/file-upload/{job_id}', body=zip_bytes, content_type='application/zip'
        )
        if status not in (200, 202, 204):
            return False, f"upload failed: HTTP {status}"

        status, _ = _bloodhound_ce_signed_request('POST', f'/api/v2/file-upload/{job_id}/end')
        if status not in (200, 202, 204):
            return False, f"closing job failed: HTTP {status}"

        return True, f"submitted (job {job_id}), ingestion queued in BloodHound CE"
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode()[:300]
        except Exception:
            detail = ''
        return False, f"HTTP {e.code} {e.reason} {detail}".strip()
    except Exception as e:
        return False, str(e)
def run_bloodhound_job(host, safe, domain, dc_host, username, secret, cred_type):
    out_dir = Path(f"{PROJECT_DIR}/scans/bloodhound")
    out_dir.mkdir(parents=True, exist_ok=True)
    final_zip = out_dir / f"{safe}.zip"
    # Run in a dedicated, empty per-run scratch dir so we can reliably find
    # the single zip bloodhound-python produces afterward without needing
    # to guess its exact auto-generated filename.
    work_dir = Path(f"{out_dir}/.{safe}_run")
    work_dir.mkdir(parents=True, exist_ok=True)
    with BLOODHOUND_STATE_LOCK:
        BLOODHOUND_STATE.update(
            running=True, host=host, log=[f"Starting BloodHound collection against {domain} via {host}"],
            started_at=datetime.now().isoformat(), finished_at=None, error=None,
        )
    cmd = ['bloodhound-python', '-u', username, '-d', domain, '-ns', host,
           '-c', 'All', '-o', str(work_dir)]
    if dc_host:
        cmd += ['-dc', dc_host]
    if cred_type == 'hash':
        cmd += ['--hashes', secret]
    else:
        cmd += ['-p', secret]
    try:
        # bloodhound-python's own source (bloodhound/__init__.py) shows its
        # zip-compression step calls os.listdir(os.getcwd()) and writes the
        # zip with a bare relative filename — it does NOT honor -o for that
        # step (only some versions honor it for the raw JSON). -o alone is
        # not enough to guarantee the zip lands in work_dir; setting cwd
        # explicitly is what actually makes os.getcwd() resolve there.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, bufsize=1, cwd=str(work_dir))
        for line in proc.stdout:
            line = line.strip()
            if line:
                with BLOODHOUND_STATE_LOCK:
                    BLOODHOUND_STATE['log'].append(line)
        proc.wait()

        if proc.returncode not in (0, None):
            with BLOODHOUND_STATE_LOCK:
                BLOODHOUND_STATE['error'] = f'bloodhound-python exited with code {proc.returncode}'
                BLOODHOUND_STATE['log'].append(f"[!] bloodhound-python exited with code {proc.returncode}")


        json_files = list(out_dir.glob('*.json'))
        print(json_files)

        if json_files:
            if final_zip.exists():
                final_zip.unlink()

            with zipfile.ZipFile(final_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                for json_file in json_files:
                    zf.write(json_file, arcname=json_file.name)

            with BLOODHOUND_STATE_LOCK:
                BLOODHOUND_STATE['log'].append(f"Collection complete — saved to {final_zip.name}")

            # Best-effort summary counts straight out of the zip's JSON files —
            # purely informational, never blocks saving the actual result.
            summary = {}

            try:
                with zipfile.ZipFile(final_zip) as zf:
                    for name in zf.namelist():
                        m = re.match(r'.*_(\w+)\.json$', name)
                        print(m)

                        if not m:
                            continue

                        kind = m.group(1)

                        try:
                            data = json.loads(zf.read(name))
                            count = len(data.get('data', []))
                            summary[kind] = count

                        except (json.JSONDecodeError, KeyError):
                            pass

            except Exception as e:
                print(e)

            try:
                for json_file in json_files:
                    if json_file.exists():
                        json_file.unlink()

                with BLOODHOUND_STATE_LOCK:
                    BLOODHOUND_STATE['log'].append(
                        f"Cleaned up {len(json_files)} BloodHound JSON files"
                    )

            except Exception as e:
                print(f"JSON cleanup failed: {e}")

            with MANIFEST_LOCK:
                manifest = load_manifest(PROJECT_DIR)
                if host in manifest:
                    manifest[host]['bloodhound_domain'] = domain
                    manifest[host]['bloodhound_scanned_at'] = datetime.now().isoformat()
                    manifest[host]['bloodhound_summary'] = summary
                    save_manifest(PROJECT_DIR, manifest)

            # Auto-submit to BloodHound CE if --bh-host/--bh-key-id/--bh-key were
            # given at startup. Never required — the zip is already safely saved
            # locally above regardless of whether this succeeds.
            if BLOODHOUND_CE:
                with BLOODHOUND_STATE_LOCK:
                    BLOODHOUND_STATE['log'].append(f"Submitting to BloodHound CE at {BLOODHOUND_CE['host']}\u2026")
                print(final_zip)
                submit_ok, submit_msg = submit_to_bloodhound_ce(final_zip.read_bytes())
                with BLOODHOUND_STATE_LOCK:
                    BLOODHOUND_STATE['log'].append(
                        (f"[+] BloodHound CE: {submit_msg}" if submit_ok else f"[!] BloodHound CE submit failed: {submit_msg}")
                    )
        else:
            with BLOODHOUND_STATE_LOCK:
                BLOODHOUND_STATE['error'] = 'bloodhound-python finished but produced no zip file'
                BLOODHOUND_STATE['log'].append('[!] No zip output found \u2014 check the log above for errors')
    except FileNotFoundError:
        with BLOODHOUND_STATE_LOCK:
            BLOODHOUND_STATE['error'] = 'bloodhound-python not found on this server'
            BLOODHOUND_STATE['log'].append('[-] bloodhound-python not found on this server')
    except Exception as e:
        with BLOODHOUND_STATE_LOCK:
            BLOODHOUND_STATE['error'] = str(e)
            BLOODHOUND_STATE['log'].append(f"[-] BloodHound job failed: {e}")
    finally:
        try:
            for f in work_dir.glob('*'):
                f.unlink()
            work_dir.rmdir()
        except OSError:
            pass
        chown_project_dir(PROJECT_DIR)
        with BLOODHOUND_STATE_LOCK:
            BLOODHOUND_STATE['running'] = False
            BLOODHOUND_STATE['finished_at'] = datetime.now().isoformat()


def compute_pwns_by_target(manifest: dict) -> dict:
    """
    Reverse-index of spray results: {target_host: [hit, ...]}.

    Credentials — and their spray_results — live under whichever host they
    were originally found on, but a hit can land on ANY host in the project.
    This flips that around so a host page (or the dashboard card) can answer
    "what creds actually work against ME" regardless of where they came from.
    """
    pwns = {}
    for source_host, r in manifest.items():
        for c in r.get('credentials', []):
            for hit in c.get('spray_results', []):
                enriched = dict(hit)
                enriched['username'] = c.get('username')
                enriched['secret'] = c.get('secret')
                enriched['cred_type'] = c.get('type')
                enriched['source_host'] = source_host
                enriched['cred_id'] = c.get('id')
                pwns.setdefault(hit['target'], []).append(enriched)
    return pwns


# ── Dashboard ─────────────────────────────────────────────────────────────────
def render_dashboard():
    manifest = load_manifest(PROJECT_DIR)
    results = sorted(manifest.values(), key=lambda r: r['host'])

    total_hosts = len(results)
    total_ports = sum(r.get('ports', 0) for r in results)
    total_exploits = sum(r.get('exploits', 0) for r in results)
    local_count = sum(1 for r in results if r.get('local'))
    proof_count = sum(1 for r in results if r.get('proof'))
    pwns_by_target = compute_pwns_by_target(manifest)

    cards = ''
    for r in results:
        safe = r['safe']
        ip = r['host']
        local, proof = bool(r.get('local')), bool(r.get('proof'))
        exploit_badge = (
            f"<div class='exploit-count has-exploits'>&#9889; {r.get('exploits', 0)} exploit hit(s)</div>"
            if r.get('exploits') else
            "<div class='exploit-count no-exploits'>No exploit hits</div>"
        )
        hits = pwns_by_target.get(ip, [])
        confident_admin_hit = any(p.get('admin') and not p.get('admin_uncertain') for p in hits)
        uncertain_admin_hit = any(p.get('admin') and p.get('admin_uncertain') for p in hits)
        pwn_badge = (
            "<span class='badge badge-red' style='margin-left:8px;vertical-align:middle'>&#128128; PWNED</span>"
            if confident_admin_hit else
            ("<span class='badge badge-orange' style='margin-left:8px;vertical-align:middle' title='Local account — UAC remote token filtering can make nxc report Pwn3d! even without genuine admin rights. Verify manually.'>&#10067; ADMIN? (unverified)</span>"
             if uncertain_admin_hit else
             ("<span class='badge badge-green' style='margin-left:8px;vertical-align:middle'>&#128273; creds work</span>"
              if hits else ''))
        )
        meta_bits = [f"&#128299; {r.get('ports', 0)} ports"]
        if r.get('hostname'):
            meta_bits.append(f"&#127991; {h(r['hostname'])}")
        if r.get('os'):
            meta_bits.append(f"&#128187; {h(r['os'].split('(')[0].strip())}")
        if r.get('services'):
            meta_bits.append(h(', '.join(r['services'][:6])))

        owned_class = ' fully-owned' if proof else ''
        cards += f"""
<div class='target-card{owned_class}' data-host='{h(ip)}'>
  <a href='/scans/html/{h(safe)}.html' style='text-decoration:none'>
    <div class='target-ip'>{h(ip)}{pwn_badge}</div>
    <div class='target-meta'>{'  '.join(f"<span>{b}</span>" for b in meta_bits)}</div>
    {exploit_badge}
  </a>
  {render_flag_chips(ip, local, proof, interactive=True)}
</div>"""

    if not results:
        cards = "<p class='empty-msg'>No hosts scanned yet — paste targets above and hit Start Scan.</p>"

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconScan — Live Dashboard</title>
{CSS}
<style>
  .scan-field {{ background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-family: var(--font-mono); padding: 6px 9px; font-size: 12px; }}
  .scan-field:focus {{ outline: none; border-color: var(--cyan); }}
  #scan-targets {{ width: 100%; resize: vertical; }}
  .scan-options {{ display: flex; gap: 16px; margin-top: 10px; flex-wrap: wrap; align-items: center; }}
  .scan-options label {{ font-size: 12px; color: var(--muted); display: flex; align-items: center; gap: 6px; }}
  #scan-submit {{ margin-left: auto; background: var(--green); color: #0d1117; border: none; border-radius: 6px; padding: 8px 20px; font-weight: 700; font-size: 13px; cursor: pointer; }}
  #scan-submit:disabled {{ opacity: .5; cursor: default; }}
  #scan-progress {{ display: none; margin-top: 18px; }}
  #scan-log {{ margin-top: 10px; max-height: 150px; overflow-y: auto; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 8px 10px; font-size: 11px; color: var(--muted); font-family: var(--font-mono); white-space: pre-wrap; }}
  .remap-collapsed {{ display: none; }}
</style>
</head>
<body>
<header>
  <span class="logo">[recon_scan]</span>
  <span style="color:var(--muted);font-size:13px"><span class="live-dot"></span>&nbsp;Live dashboard &mdash; {h(PROJECT_DIR)}</span>
  <nav>
    <a href="/credentials" style="color:var(--cyan);font-size:12px;text-decoration:none;margin-right:14px">&#128273; Credentials</a>
    <span style="color:var(--muted);font-size:12px;font-family:var(--font-mono)" id="clock"></span>
  </nav>
</header>
<div class="container">
  <h1>Scan Results</h1>
  <p class="subtitle">Check off Local/Proof as you land flags &mdash; saved instantly, synced across tabs.</p>

  <div class="card">
    <div class="card-header"><h2>&#127919; Scan Hosts</h2></div>
    <div class="card-body">
      <form id="scan-form" onsubmit="startScan(event)">
        <textarea id="scan-targets" class="scan-field" rows="4" placeholder="10.10.10.5&#10;10.10.10.0/24&#10;# comments allowed, one target per line"></textarea>
        <div class="scan-options">
          <label>Threads <input id="scan-threads" class="scan-field" type="number" min="1" max="20" value="5" style="width:55px"></label>
          <label>Ports <input id="scan-ports" class="scan-field" type="text" value="--top-ports 10000" style="width:170px"></label>
          <label><input id="scan-no-udp" type="checkbox"> Skip UDP</label>
          <button type="submit" id="scan-submit">Start Scan</button>
        </div>
      </form>
      <div id="scan-progress">
        <div class="progress-label"><span id="scan-progress-text"></span><span id="scan-current" style="color:var(--cyan)"></span></div>
        <div class="progress-track"><div class="progress-fill-local" id="scan-progress-fill" style="width:0%"></div></div>
        <pre id="scan-log"></pre>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-header" style="cursor:pointer" onclick="document.getElementById('remap-body').classList.toggle('remap-collapsed')">
      <h2>&#128260; Lab Restarted? Remap IPs</h2>
    </div>
    <div class="card-body remap-collapsed" id="remap-body">
      <p class="subtitle" style="margin:0 0 10px">
        PEN-200 lab restarts often reassign the third octet of every host
        (e.g. <code>.50.x</code> &#8594; <code>.150.x</code>). This renames
        everything in place &mdash; no rescanning. Notes, credentials, and
        Local/Proof flags all carry over.
      </p>
      <div class="scan-options" style="margin-top:0">
        <label>Old octet <input id="remap-old" class="scan-field" type="text" placeholder="50" style="width:70px"></label>
        <label>New octet <input id="remap-new" class="scan-field" type="text" placeholder="150" style="width:70px"></label>
        <button type="button" class="scan-field" style="cursor:pointer;background:var(--cyan);color:#0d1117;font-weight:700;border:none" onclick="previewRemap()">Preview</button>
        <button type="button" id="remap-apply-btn" class="scan-field" style="cursor:pointer;background:var(--red);color:#fff;font-weight:700;border:none;display:none" onclick="applyRemap()">Apply Remap</button>
      </div>
      <div id="remap-result" style="margin-top:10px;font-size:12px"></div>
    </div>
  </div>

  <div class="card">
    <div class="card-header" style="cursor:pointer" onclick="document.getElementById('report-body').classList.toggle('remap-collapsed')">
      <h2>&#128196; Generate Report</h2>
    </div>
    <div class="card-body remap-collapsed" id="report-body">
      <p class="subtitle" style="margin:0 0 10px">
        Builds a .docx exam report from every Local/Proof-flagged host &mdash;
        enumeration, attack narrative, and pivoting from notes, credentials
        from the manifest. Hashes/screenshots/AD narrative are left as
        placeholders to fill in by hand, same as the template itself.
      </p>
      <div class="scan-options" style="margin-top:0">
        <label>Candidate <input id="report-candidate" class="scan-field" type="text" placeholder="Your Name" style="width:140px"></label>
        <label>OSID <input id="report-osid" class="scan-field" type="text" placeholder="OS-12345" style="width:100px"></label>
        <label>Email <input id="report-email" class="scan-field" type="text" placeholder="you@example.com" style="width:170px"></label>
        <label>Exam Date <input id="report-date" class="scan-field" type="text" placeholder="2026-07-14" style="width:110px"></label>
      </div>
      <div class="scan-options" style="margin-top:8px">
        <label><input id="report-all" type="checkbox"> Include every host, not just Local/Proof-flagged</label>
        <button type="button" class="scan-field" style="cursor:pointer;background:var(--green);color:#0d1117;font-weight:700;border:none" onclick="generateReport()">Download Report</button>
      </div>
    </div>
  </div>

  <div class="stat-row">
    <div class="stat"><div class="val">{total_hosts}</div><div class="lbl">Hosts</div></div>
    <div class="stat"><div class="val">{total_ports}</div><div class="lbl">Open Ports</div></div>
    <div class="stat"><div class="val" style="color:var(--red)">{total_exploits}</div><div class="lbl">Exploit Hits</div></div>
    <div class="stat"><div class="val" style="color:var(--green)" id="local-stat">{local_count}/{total_hosts}</div><div class="lbl">Local</div></div>
    <div class="stat"><div class="val" style="color:var(--purple)" id="proof-stat">{proof_count}/{total_hosts}</div><div class="lbl">Proof</div></div>
  </div>
  <input class="search-bar" id="search" type="text" placeholder="Filter by IP, hostname, or service..." oninput="filterCards()">
  <div class="toolbar-row">
    <div class="progress-wrap">
      <div class="progress-label"><span>Local</span><span>Proof</span></div>
      <div class="progress-track">
        <div class="progress-fill-local" id="progress-local" style="width:{(local_count/total_hosts*100) if total_hosts else 0:.0f}%"></div>
        <div class="progress-fill-proof" id="progress-proof" style="width:{(proof_count/total_hosts*100) if total_hosts else 0:.0f}%"></div>
      </div>
    </div>
    <label class="hide-completed-toggle">
      <input type="checkbox" id="hide-done" onchange="toggleHideDone()"> Hide fully-owned hosts
    </label>
  </div>
  <div class="grid" id="grid">{cards}</div>
</div>
<footer>recon_scan.py &nbsp;&middot;&nbsp; live via recon_server.py</footer>
<div class="save-toast" id="toast">Saved</div>
<script>
let knownMtime = {manifest_mtime()};
let saving = false;
let scanInProgress = false;

function showToast(msg) {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(showToast._h);
  showToast._h = setTimeout(() => t.classList.remove('show'), 1500);
}}

function setFlag(host, field, value, checkbox) {{
  saving = true;
  const card = checkbox.closest('.target-card');
  fetch('/api/status/' + encodeURIComponent(host), {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{field: field, value: value}})
  }})
  .then(r => {{ if (!r.ok) throw new Error('save failed'); return r.json(); }})
  .then(data => {{
    knownMtime = data.mtime;
    checkbox.closest('.flag-chip').classList.toggle('on', value);
    if (field === 'local') card.dataset.local = value ? '1' : '0';
    if (field === 'proof') card.dataset.proof = value ? '1' : '0';
    card.classList.toggle('fully-owned', card.dataset.local === '1' && card.dataset.proof === '1');
    showToast((value ? 'Marked ' : 'Unmarked ') + field);
    updateStats();
  }})
  .catch(() => {{
    checkbox.checked = !value;
    showToast('Save failed — check the server');
  }})
  .finally(() => {{ saving = false; }});
}}

function updateStats() {{
  const total = document.querySelectorAll('.target-card').length;
  const local = document.querySelectorAll('.flag-chip.on:not(.proof)').length;
  const proof = document.querySelectorAll('.flag-chip.proof.on').length;
  document.getElementById('local-stat').textContent = local + '/' + total;
  document.getElementById('proof-stat').textContent = proof + '/' + total;
  document.getElementById('progress-local').style.width = (total ? Math.round(local/total*100) : 0) + '%';
  document.getElementById('progress-proof').style.width = (total ? Math.round(proof/total*100) : 0) + '%';
}}

function toggleHideDone() {{
  document.getElementById('grid').classList.toggle('hide-done', document.getElementById('hide-done').checked);
}}

function filterCards() {{
  const q = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('#grid > .target-card').forEach(c => {{
    c.classList.toggle('hidden', !c.textContent.toLowerCase().includes(q));
  }});
}}

function tickClock() {{
  document.getElementById('clock').textContent = new Date().toLocaleString();
}}
setInterval(tickClock, 1000); tickClock();

// ── Remap IPs (lab restart) ─────────────────────────────────────────────────
function renderRemapResult(data) {{
  const el = document.getElementById('remap-result');
  const applyBtn = document.getElementById('remap-apply-btn');
  let html = '';

  if (data.to_remap.length) {{
    html += '<div style="color:var(--green)">' + data.to_remap.length + ' host(s) ' +
      (data.applied ? 'remapped:' : 'would be remapped:') + '</div>';
    html += data.to_remap.map(m => '&nbsp;&nbsp;' + m.old + ' &#8594; ' + m.new).join('<br>');
  }} else {{
    html += '<div style="color:var(--muted)">No hosts matched that octet.</div>';
  }}
  if (data.skipped_collision.length) {{
    html += '<div style="color:var(--red);margin-top:6px">' + data.skipped_collision.length +
      ' skipped &mdash; target IP already exists:</div>';
    html += data.skipped_collision.map(m => '&nbsp;&nbsp;' + m.old + ' &#8594; ' + m.new).join('<br>');
  }}
  el.innerHTML = html;
  applyBtn.style.display = (data.to_remap.length && !data.applied) ? 'inline-block' : 'none';
}}

function previewRemap() {{
  const old_octet = document.getElementById('remap-old').value.trim();
  const new_octet = document.getElementById('remap-new').value.trim();
  if (!old_octet || !new_octet) {{ showToast('Enter both octets'); return; }}
  fetch('/api/remap', {{
    method: 'POST', headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{old_octet: old_octet, new_octet: new_octet, dry_run: true}})
  }})
  .then(r => r.json().then(d => {{ if (!r.ok) throw new Error(d.description || 'preview failed'); return d; }}))
  .then(renderRemapResult)
  .catch(e => showToast('Preview failed: ' + e.message));
}}

function applyRemap() {{
  const old_octet = document.getElementById('remap-old').value.trim();
  const new_octet = document.getElementById('remap-new').value.trim();
  if (!confirm('Remap all matching hosts from .' + old_octet + '. to .' + new_octet + '.? ' +
               'This renames files in place — notes and credentials carry over, nothing is rescanned.')) return;
  fetch('/api/remap', {{
    method: 'POST', headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{old_octet: old_octet, new_octet: new_octet, dry_run: false}})
  }})
  .then(r => r.json().then(d => {{ if (!r.ok) throw new Error(d.description || 'remap failed'); return d; }}))
  .then(data => {{ renderRemapResult(data); showToast('Remap applied'); setTimeout(() => window.location.reload(), 1200); }})
  .catch(e => showToast('Remap failed: ' + e.message));
}}

function generateReport() {{
  const params = new URLSearchParams({{
    candidate: document.getElementById('report-candidate').value,
    osid: document.getElementById('report-osid').value,
    email: document.getElementById('report-email').value,
    exam_date: document.getElementById('report-date').value,
    all: document.getElementById('report-all').checked ? '1' : '0',
  }});
  // GET with as_attachment triggers a normal browser download without
  // navigating away — no fetch/blob juggling needed for a simple download.
  window.location.href = '/api/report/docx?' + params.toString();
  showToast('Generating report\u2026');
}}

// ── Scan launcher ────────────────────────────────────────────────────────────
function startScan(evt) {{
  evt.preventDefault();
  const targets = document.getElementById('scan-targets').value;
  if (!targets.trim()) {{ showToast('Enter at least one target'); return; }}
  const threads = parseInt(document.getElementById('scan-threads').value) || 5;
  const ports = document.getElementById('scan-ports').value.trim() || '--top-ports 10000';
  const no_udp = document.getElementById('scan-no-udp').checked;

  document.getElementById('scan-submit').disabled = true;
  fetch('/api/scan', {{
    method: 'POST', headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{targets: targets, threads: threads, ports: ports, no_udp: no_udp}})
  }})
  .then(r => {{
    if (!r.ok) return r.json().then(d => {{ throw new Error(d.description || 'failed to start scan'); }});
    return r.json();
  }})
  .then(() => {{
    scanInProgress = true;
    document.getElementById('scan-progress').style.display = 'block';
    pollScanStatus();
  }})
  .catch(e => {{
    showToast('Could not start scan: ' + e.message);
    document.getElementById('scan-submit').disabled = false;
  }});
}}

function renderScanStatus(s) {{
  if (s.total || s.running) document.getElementById('scan-progress').style.display = 'block';
  document.getElementById('scan-progress-text').textContent = s.done + '/' + s.total + ' host(s) scanned';
  document.getElementById('scan-current').textContent = (s.remaining && s.remaining.length && s.running)
    ? ('queued/running: ' + s.remaining.slice(0, 6).join(', ') + (s.remaining.length > 6 ? '…' : ''))
    : '';
  document.getElementById('scan-progress-fill').style.width = (s.total ? Math.round(s.done / s.total * 100) : 0) + '%';
  document.getElementById('scan-log').textContent = (s.log || []).slice(-15).join('\\n');
  document.getElementById('scan-submit').disabled = !!s.running;
}}

function pollScanStatus() {{
  fetch('/api/scan/status').then(r => r.json()).then(s => {{
    renderScanStatus(s);
    if (s.running) {{
      scanInProgress = true;
      setTimeout(pollScanStatus, 1500);
    }} else if (scanInProgress) {{
      scanInProgress = false;
      location.reload();
    }}
  }}).catch(() => {{}});
}}
pollScanStatus(); // resume showing progress if a scan is already running (e.g. after page reload)

// Poll for changes from other tabs / an in-progress scan / a headless
// recon_scan.py run; reload if something changed that we didn't just save.
setInterval(() => {{
  if (saving || scanInProgress) return;
  fetch('/api/hosts').then(r => r.json()).then(data => {{
    if (data.mtime !== knownMtime) location.reload();
  }}).catch(() => {{}});
}}, 8000);
</script>
</body>
</html>"""
    return page


# ── Credentials page ─────────────────────────────────────────────────────────
def render_credentials_page():
    manifest = load_manifest(PROJECT_DIR)
    results = sorted(manifest.values(), key=lambda r: r['host'])

    flat = []
    for r in results:
        for c in r.get('credentials', []):
            flat.append((r['host'], c))
    flat.sort(key=lambda t: (t[1].get('username', ''), t[0]))

    def status_badge_class(s):
        return {'valid-admin': 'badge-red', 'valid-admin-uncertain': 'badge-orange',
                'valid': 'badge-green', 'invalid': 'badge-muted'}.get(s, 'badge-orange')

    rows = ''
    for host, c in flat:
        hit_count = len(c.get('spray_results', []))
        admin_count = sum(1 for hh in c.get('spray_results', []) if hh.get('admin') and not hh.get('admin_uncertain'))
        uncertain_count = sum(1 for hh in c.get('spray_results', []) if hh.get('admin') and hh.get('admin_uncertain'))
        hit_summary = (
            (f"<span class='badge badge-red'>{admin_count} admin</span> " if admin_count else '') +
            (f"<span class='badge badge-orange' title='Local account — UAC remote token filtering can make nxc report Pwn3d! even without genuine admin rights. Verify manually.'>{uncertain_count} admin?</span> " if uncertain_count else '') +
            (f"<span class='badge badge-green'>{hit_count} hit(s)</span>" if hit_count else
             "<span class='badge badge-muted'>not sprayed</span>")
        )

        rows += f"""
<tr data-cred-row="{h(c['id'])}">
  <td><a href="/scans/html/{h(manifest[host]['safe'])}.html" style="color:var(--cyan)">{h(host)}</a></td>
  <td>{h(c.get('username',''))}</td>
  <td><code>{h(c.get('secret',''))}</code></td>
  <td>{h(c.get('type',''))}</td>
  <td>{h(c.get('service','') or '—')}</td>
  <td><span class="badge {status_badge_class(c.get('status'))}">{h(c.get('status',''))}</span></td>
  <td>{hit_summary}</td>
  <td>
    <button class="scan-field" style="cursor:pointer;border:none;background:var(--green);color:#0d1117;font-weight:700" onclick="spray('{h(host)}','{h(c['id'])}','{h(c.get('username',''))}')">Spray</button>
    <button class="scan-field" style="cursor:pointer;border:none;background:var(--red);color:#fff" onclick="deleteCredGlobal('{h(host)}','{h(c['id'])}')">&times;</button>
  </td>
</tr>"""

        if c.get('spray_results'):
            def _result_label(hh):
                if hh.get('admin') and hh.get('admin_uncertain'):
                    return "<span title='Local account — UAC remote token filtering can make nxc report Pwn3d! even without genuine admin rights. Verify manually.'>&#128081; admin? (unverified)</span>"
                if hh.get('admin'):
                    return "&#128081; admin"
                return "valid"
            hit_rows = ''.join(
                f"<tr><td>{h(hh['target'])}</td><td>{h(hh['protocol'])}</td><td>{h(hh['mode'])}</td>"
                f"<td>{_result_label(hh)}</td>"
                f"<td>{h(', '.join(hh.get('shares', []))) or '—'}</td></tr>"
                for hh in c['spray_results']
            )
            rows += f"""
<tr class="hit-detail-row">
  <td colspan="8" style="padding:0 0 14px 24px;border:none">
    <table class="port-table" style="margin-top:6px">
      <thead><tr><th>Target</th><th>Protocol</th><th>Mode</th><th>Result</th><th>Shares</th></tr></thead>
      <tbody>{hit_rows}</tbody>
    </table>
  </td>
</tr>"""

    if not flat:
        rows = "<tr><td colspan='8' class='empty-msg'>No credentials recorded yet — add them from a host's page.</td></tr>"

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconScan — Credentials</title>
{CSS}
<style>
  .scan-field {{ background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-family: var(--font-mono); padding: 6px 9px; font-size: 12px; }}
  #spray-progress {{ display: none; margin: 16px 0; }}
  #spray-log {{ margin-top: 10px; max-height: 150px; overflow-y: auto; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 8px 10px; font-size: 11px; color: var(--muted); font-family: var(--font-mono); white-space: pre-wrap; }}
</style>
</head>
<body>
<header>
  <span class="logo">[recon_scan]</span>
  <span style="color:var(--muted);font-size:13px"><span class="live-dot"></span>&nbsp;Live dashboard &mdash; {h(PROJECT_DIR)}</span>
  <nav>
    <a href="/" style="color:var(--cyan);font-size:12px;text-decoration:none;margin-right:14px">&#127919; Dashboard</a>
    <span style="color:var(--muted);font-size:12px;font-family:var(--font-mono)" id="clock"></span>
  </nav>
</header>
<div class="container">
  <h1>Credentials</h1>
  <p class="subtitle">Every credential across every host in this project. Spray any of them against all known hosts, all protocols, in one click.</p>

  <div class="toolbar-row">
    <button class="scan-field" id="spray-all-btn" style="cursor:pointer;border:none;background:var(--purple);color:#fff;font-weight:700;padding:8px 16px;margin-left:auto" onclick="sprayAll()">&#9889; Spray All Credentials</button>
  </div>

  <div id="spray-progress" class="card">
    <div class="card-body">
      <div class="progress-label"><span id="spray-progress-text"></span></div>
      <div class="progress-track"><div class="progress-fill-local" id="spray-progress-fill" style="width:0%"></div></div>
      <pre id="spray-log"></pre>
    </div>
  </div>

  <div class="card">
    <div class="card-body">
      <table class="port-table" id="creds-table">
        <thead><tr><th>Host</th><th>User</th><th>Secret</th><th>Type</th><th>Service</th><th>Status</th><th>Spray Results</th><th></th></tr></thead>
        <tbody id="creds-tbody">{rows}</tbody>
      </table>
    </div>
  </div>
</div>
<footer>recon_scan.py &nbsp;&middot;&nbsp; live via recon_server.py</footer>
<div class="save-toast" id="toast">Saved</div>
<script>
function showToast(msg) {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(showToast._h);
  showToast._h = setTimeout(() => t.classList.remove('show'), 1500);
}}

function tickClock() {{ document.getElementById('clock').textContent = new Date().toLocaleString(); }}
setInterval(tickClock, 1000); tickClock();

let sprayInProgress = false;

function spray(host, credId, username) {{
  fetch('/api/spray/' + encodeURIComponent(host) + '/' + encodeURIComponent(credId), {{ method: 'POST' }})
    .then(r => {{
      if (!r.ok) return r.json().then(d => {{ throw new Error(d.description || 'failed to start spray'); }});
      return r.json();
    }})
    .then(() => {{
      sprayInProgress = true;
      document.getElementById('spray-progress').style.display = 'block';
      showToast('Spraying ' + username + ' against all hosts...');
      pollSprayStatus();
    }})
    .catch(e => showToast('Could not start spray: ' + e.message));
}}

function sprayAll() {{
  if (!confirm('Spray every stored credential against every known host? This can take a while with a lot of creds.')) return;
  fetch('/api/spray-all', {{ method: 'POST' }})
    .then(r => {{
      if (!r.ok) return r.json().then(d => {{ throw new Error(d.description || 'failed to start spray'); }});
      return r.json();
    }})
    .then(data => {{
      sprayInProgress = true;
      document.getElementById('spray-progress').style.display = 'block';
      showToast('Spraying ' + data.count + ' credential(s) against all hosts...');
      pollSprayStatus();
    }})
    .catch(e => showToast('Could not start spray: ' + e.message));
}}

function renderSprayStatus(s) {{
  document.getElementById('spray-progress-text').textContent =
    (s.label ? ('Spraying ' + s.label + ' — ') : '') + s.done + '/' + s.total + ' check(s)';
  document.getElementById('spray-progress-fill').style.width = (s.total ? Math.round(s.done / s.total * 100) : 0) + '%';
  document.getElementById('spray-log').textContent = (s.log || []).slice(-20).join('\\n');
  document.getElementById('spray-all-btn').disabled = !!s.running;
}}

function pollSprayStatus() {{
  fetch('/api/spray/status').then(r => r.json()).then(s => {{
    renderSprayStatus(s);
    if (s.running) {{
      sprayInProgress = true;
      document.getElementById('spray-progress').style.display = 'block';
      setTimeout(pollSprayStatus, 1500);
    }} else if (sprayInProgress) {{
      sprayInProgress = false;
      showToast('Spray complete');
      setTimeout(() => location.reload(), 800);
    }}
  }}).catch(() => {{}});
}}
pollSprayStatus(); // resume showing progress if a spray is already running

function deleteCredGlobal(host, credId) {{
  if (!confirm('Delete this credential?')) return;
  fetch('/api/creds/' + encodeURIComponent(host) + '/' + encodeURIComponent(credId), {{ method: 'DELETE' }})
    .then(r => {{ if (!r.ok) throw new Error('delete failed'); return r.json(); }})
    .then(() => location.reload())
    .catch(() => showToast('Could not delete credential'));
}}
</script>
</body>
</html>"""
    return page


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
@app.route('/index.html')
def dashboard():
    return render_dashboard()


@app.route('/credentials')
def credentials_page():
    return render_credentials_page()


@app.route('/scans/html/<path:filename>')
def serve_report(filename):
    d = PROJECT_DIR / 'scans' / 'html'
    if not (d / filename).exists():
        abort(404)
    return send_from_directory(d, filename)


@app.route('/scans/nmap/<path:filename>')
def serve_nmap(filename):
    d = PROJECT_DIR / 'scans' / 'nmap'
    if not (d / filename).exists():
        abort(404)
    return send_from_directory(d, filename)


@app.route('/scans/searchsploit/<path:filename>')
def serve_searchsploit(filename):
    d = PROJECT_DIR / 'scans' / 'searchsploit'
    if not (d / filename).exists():
        abort(404)
    return send_from_directory(d, filename, mimetype='text/plain')


@app.route('/notes/<path:filename>')
def serve_note(filename):
    d = PROJECT_DIR / 'notes'
    if not (d / filename).exists():
        abort(404)
    return send_from_directory(d, filename, mimetype='text/plain', as_attachment=True)


@app.route('/api/hosts')
def api_hosts():
    manifest = load_manifest(PROJECT_DIR)
    return jsonify(hosts=list(manifest.values()), mtime=manifest_mtime())


@app.route('/api/status/<host>', methods=['POST'])
def api_set_status(host):
    data = request.get_json(silent=True) or {}
    field = data.get('field')
    value = bool(data.get('value'))
    if field not in ('local', 'proof'):
        return jsonify(ok=False, description="field must be 'local' or 'proof'"), 400

    with MANIFEST_LOCK:
        manifest = load_manifest(PROJECT_DIR)
        if host not in manifest:
            return jsonify(ok=False, description=f"host {host} not found in project"), 404
        manifest[host][field] = value
        manifest[host][f'{field}_updated_at'] = datetime.now().isoformat() if value else None
        save_manifest(PROJECT_DIR, manifest)
        mtime = manifest_mtime()
    chown_project_dir(PROJECT_DIR)

    return jsonify(ok=True, host=host, field=field, value=value, mtime=mtime)


@app.route('/api/scan', methods=['POST'])
def api_start_scan():
    data = request.get_json(silent=True) or {}
    raw = data.get('targets', '')
    targets = [ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.strip().startswith('#')]
    if not targets:
        return jsonify(ok=False, description="No targets provided"), 400

    try:
        threads = max(1, min(20, int(data.get('threads', 5))))
    except (TypeError, ValueError):
        threads = 5
    ports = (data.get('ports') or '--top-ports 10000').strip()
    no_udp = bool(data.get('no_udp', False))

    if not shutil.which('nmap'):
        return jsonify(ok=False, description="nmap not found on this server"), 500

    with STATE_LOCK:
        if SCAN_STATE['running']:
            return jsonify(ok=False, description="A scan is already in progress"), 409

    threading.Thread(
        target=run_scan_job, args=(targets, threads, ports, not no_udp, PROXY_PORT), daemon=True
    ).start()
    return jsonify(ok=True, targets=targets)


@app.route('/api/scan/status')
def api_scan_status():
    with STATE_LOCK:
        return jsonify(dict(SCAN_STATE))


@app.route('/api/spray/<host>/<cred_id>', methods=['POST'])
def api_start_spray(host, cred_id):
    with MANIFEST_LOCK:
        manifest = load_manifest(PROJECT_DIR)
        if host not in manifest:
            return jsonify(ok=False, description=f"host {host} not found in project"), 404
        cred = next((c for c in manifest[host].get('credentials', []) if c.get('id') == cred_id), None)
        if cred is None:
            return jsonify(ok=False, description=f"credential {cred_id} not found"), 404
        username, secret = cred['username'], cred['secret']

    if not shutil.which('nxc') and not shutil.which('netexec'):
        return jsonify(ok=False, description="nxc/netexec not found on this server"), 500

    with SPRAY_STATE_LOCK:
        if SPRAY_STATE['running']:
            return jsonify(ok=False, description="A spray is already in progress"), 409

    spray_targets = [{'source_host': host, 'cred_id': cred_id, 'username': username, 'secret': secret}]
    threading.Thread(
        target=run_spray_job, args=(spray_targets, f"'{username}'"), daemon=True
    ).start()
    return jsonify(ok=True, host=host, cred_id=cred_id, username=username)


@app.route('/api/spray-all', methods=['POST'])
def api_start_spray_all():
    with MANIFEST_LOCK:
        manifest = load_manifest(PROJECT_DIR)
        spray_targets = [
            {'source_host': host, 'cred_id': c['id'], 'username': c['username'], 'secret': c['secret']}
            for host, r in manifest.items()
            for c in r.get('credentials', [])
        ]

    if not spray_targets:
        return jsonify(ok=False, description="No credentials recorded in this project yet"), 400
    if not shutil.which('nxc') and not shutil.which('netexec'):
        return jsonify(ok=False, description="nxc/netexec not found on this server"), 500

    with SPRAY_STATE_LOCK:
        if SPRAY_STATE['running']:
            return jsonify(ok=False, description="A spray is already in progress"), 409

    threading.Thread(
        target=run_spray_job, args=(spray_targets, f"{len(spray_targets)} credential(s)"), daemon=True
    ).start()
    return jsonify(ok=True, count=len(spray_targets))


@app.route('/api/spray/status')
def api_spray_status():
    with SPRAY_STATE_LOCK:
        return jsonify(dict(SPRAY_STATE))


@app.route('/api/ferox/<host>', methods=['GET', 'POST'])
def api_ferox(host):
    with MANIFEST_LOCK:
        manifest = load_manifest(PROJECT_DIR)
        if host not in manifest:
            return jsonify(ok=False, description=f"host {host} not found in project"), 404
        record = manifest[host]
        safe = record.get('safe') or host.replace('/', '_').replace('.', '-')

        if request.method == 'GET':
            hits = record.get('ferox', [])
            show_all = request.args.get('all', '').lower() in ('1', 'true', 'yes')
            if not show_all:
                hits = [h for h in hits if _is_interesting_ferox_status(h.get('status'))]
            return jsonify(
                ok=True,
                hits=hits,
                target_url=record.get('ferox_target_url'),
                scanned_at=record.get('ferox_scanned_at'),
            )

    # POST — start a new scan
    data = request.get_json(silent=True) or {}
    url = (data.get('url') or '').strip()
    if not url:
        return jsonify(ok=False, description="url is required"), 400
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    wordlist = (data.get('wordlist') or '').strip() or FEROX_DEFAULT_WORDLIST
    if not Path(wordlist).exists():
        return jsonify(ok=False, description=f"wordlist not found: {wordlist}"), 400

    extensions = (data.get('extensions') or '').strip()
    threads = data.get('threads')
    try:
        threads = int(threads) if threads else None
    except (TypeError, ValueError):
        threads = None
    # Default True (disable feroxbuster's wildcard auto-filter) — see the
    # comment in run_ferox_job for why this matters. 'dont_filter': false
    # explicitly re-enables feroxbuster's own filtering, e.g. for a target
    # with a genuine wildcard vhost where you want that noise suppressed.
    dont_filter = data.get('dont_filter', True)
    # Default True (only surface 2xx/3xx hits) — a raw wordlist scan is
    # overwhelmingly 404s, which is normal and not worth cluttering the
    # dashboard with. 'status_filter': false shows everything, including
    # 404s — the full untouched output is always on disk either way.
    status_filter = data.get('status_filter', True)

    if not shutil.which('feroxbuster'):
        return jsonify(ok=False, description="feroxbuster not found on this server"), 500

    with FEROX_STATE_LOCK:
        if FEROX_STATE['running']:
            return jsonify(ok=False, description="A feroxbuster scan is already in progress"), 409

    threading.Thread(
        target=run_ferox_job, args=(host, safe, url, wordlist, extensions, threads, dont_filter, status_filter), daemon=True
    ).start()
    return jsonify(ok=True, host=host, url=url)


@app.route('/api/ferox/status')
def api_ferox_status():
    with FEROX_STATE_LOCK:
        return jsonify(dict(FEROX_STATE))


@app.route('/api/bloodhound/<host>', methods=['GET', 'POST'])
def api_bloodhound(host):
    with MANIFEST_LOCK:
        manifest = load_manifest(PROJECT_DIR)
        if host not in manifest:
            return jsonify(ok=False, description=f"host {host} not found in project"), 404
        record = manifest[host]
        safe = record.get('safe') or host.replace('/', '_').replace('.', '-')

        if request.method == 'GET':
            candidates = find_ldap_credentials(manifest, host)
            note_path = PROJECT_DIR / 'notes' / f"{host}.md"
            note_text = note_path.read_text(encoding='utf-8', errors='ignore') if note_path.exists() else ''
            suggested_domain = parse_domain_from_note(note_text)

            last_run = None
            if record.get('bloodhound_scanned_at'):
                zip_path = PROJECT_DIR / 'scans' / 'bloodhound' / f"{safe}.zip"
                if zip_path.exists():
                    last_run = {
                        'scanned_at': record.get('bloodhound_scanned_at'),
                        'domain': record.get('bloodhound_domain'),
                        'summary': record.get('bloodhound_summary', {}),
                        'zip_url': f"/scans/bloodhound/{safe}.zip",
                    }

            return jsonify(
                ok=True,
                credentials=[{k: c[k] for k in ('source_host', 'cred_id', 'username', 'status')} for c in candidates],
                suggested_domain=suggested_domain,
                last_run=last_run,
            )

    # POST — start a new collection
    data = request.get_json(silent=True) or {}
    source_host = data.get('source_host', '')
    cred_id = data.get('cred_id', '')
    domain = (data.get('domain') or '').strip()
    dc_host = (data.get('dc') or '').strip()

    if not domain:
        return jsonify(ok=False, description="domain is required"), 400
    if not source_host or not cred_id:
        return jsonify(ok=False, description="no credential selected"), 400

    with MANIFEST_LOCK:
        manifest = load_manifest(PROJECT_DIR)
        source_record = manifest.get(source_host)
        if not source_record:
            return jsonify(ok=False, description=f"credential's source host {source_host} not found"), 404
        cred = next((c for c in source_record.get('credentials', []) if c.get('id') == cred_id), None)
        if not cred:
            return jsonify(ok=False, description="credential not found — it may have been deleted"), 404

    if not shutil.which('bloodhound-python'):
        return jsonify(ok=False, description="bloodhound-python not found on this server"), 500

    with BLOODHOUND_STATE_LOCK:
        if BLOODHOUND_STATE['running']:
            return jsonify(ok=False, description="A BloodHound collection is already in progress"), 409

    manifest = load_manifest(PROJECT_DIR)
    safe = manifest[host].get('safe') or host.replace('/', '_').replace('.', '-')
    threading.Thread(
        target=run_bloodhound_job,
        args=(host, safe, domain, dc_host, cred.get('username', ''), cred.get('secret', ''), cred.get('type', 'password')),
        daemon=True,
    ).start()
    return jsonify(ok=True, host=host, domain=domain)


@app.route('/api/bloodhound/status')
def api_bloodhound_status():
    with BLOODHOUND_STATE_LOCK:
        return jsonify(dict(BLOODHOUND_STATE))


@app.route('/scans/bloodhound/<path:filename>')
def serve_bloodhound(filename):
    d = PROJECT_DIR / 'scans' / 'bloodhound'
    if not (d / filename).exists():
        abort(404)
    return send_from_directory(d, filename, mimetype='application/zip', as_attachment=True)


@app.route('/api/pwns/<host>')
def api_pwns(host):
    manifest = load_manifest(PROJECT_DIR)
    pwns = compute_pwns_by_target(manifest).get(host, [])
    return jsonify(ok=True, pwns=pwns)


@app.route('/api/creds/<host>', methods=['GET', 'POST'])
def api_creds(host):
    with MANIFEST_LOCK:
        manifest = load_manifest(PROJECT_DIR)
        if host not in manifest:
            return jsonify(ok=False, description=f"host {host} not found in project"), 404

        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            username = (data.get('username') or '').strip()
            secret = (data.get('secret') or '').strip()
            if not username or not secret:
                return jsonify(ok=False, description="username and secret are required"), 400
            cred = {
                'id': uuid.uuid4().hex[:8],
                'username': username,
                'secret': secret,
                'type': data.get('type') or 'password',
                'service': (data.get('service') or '').strip(),
                'status': data.get('status') or 'untested',
                'notes': (data.get('notes') or '').strip(),
                'added_at': datetime.now().isoformat(),
            }
            manifest[host].setdefault('credentials', []).append(cred)
            save_manifest(PROJECT_DIR, manifest)
            write_creds_files(PROJECT_DIR, manifest)
            append_cred_to_note(PROJECT_DIR, host, cred)
            chown_project_dir(PROJECT_DIR)

        creds = manifest[host].get('credentials', [])
    return jsonify(ok=True, credentials=creds)


@app.route('/api/creds/<host>/<cred_id>', methods=['DELETE', 'PATCH'])
def api_cred_detail(host, cred_id):
    with MANIFEST_LOCK:
        manifest = load_manifest(PROJECT_DIR)
        if host not in manifest:
            return jsonify(ok=False, description=f"host {host} not found in project"), 404
        creds = manifest[host].get('credentials', [])

        if request.method == 'DELETE':
            creds = [c for c in creds if c.get('id') != cred_id]
        else:  # PATCH — update status/notes on an existing credential
            data = request.get_json(silent=True) or {}
            found = False
            for c in creds:
                if c.get('id') == cred_id:
                    if 'status' in data:
                        c['status'] = data['status']
                    if 'notes' in data:
                        c['notes'] = data['notes']
                    found = True
                    break
            if not found:
                return jsonify(ok=False, description=f"credential {cred_id} not found"), 404

        manifest[host]['credentials'] = creds
        save_manifest(PROJECT_DIR, manifest)
        write_creds_files(PROJECT_DIR, manifest)
    chown_project_dir(PROJECT_DIR)
    return jsonify(ok=True, credentials=creds)


@app.route('/api/report/docx')
def api_report_docx():
    """
    Generates the .docx exam report on demand and streams it straight back
    as a download — nothing is written to disk on the server side beyond
    what generate_docx_report itself needs, and no state to poll; this is
    fast enough (a handful of hosts' worth of notes) to do synchronously
    in the request.
    """
    if recon_report_docx is None:
        return jsonify(ok=False, description="python-docx not installed on this server — "
                                               "pip install python-docx --break-system-packages"), 500

    include_all = request.args.get('all', '').lower() in ('1', 'true', 'yes')
    candidate = request.args.get('candidate', '')
    osid = request.args.get('osid', '')
    email = request.args.get('email', '')
    exam_date = request.args.get('exam_date', '')

    try:
        doc = recon_report_docx.generate_docx_report(
            PROJECT_DIR, include_all=include_all,
            candidate=candidate, osid=osid, email=email, exam_date=exam_date,
        )
    except Exception as e:
        return jsonify(ok=False, description=f"report generation failed: {e}"), 500

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return send_file(
        buf, as_attachment=True, download_name='FINAL_REPORT.docx',
        mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    )


@app.route('/api/remap', methods=['POST'])
def api_remap():
    """
    Lab restarts often reassign the third octet of every host's IP. This
    re-keys the manifest and renames every associated file in place —
    no rescanning, notes/credentials/flags all carry over untouched.
    """
    data = request.get_json(silent=True) or {}
    old_octet = str(data.get('old_octet', '')).strip()
    new_octet = str(data.get('new_octet', '')).strip()
    dry_run = bool(data.get('dry_run', True))

    if not old_octet.isdigit() or not new_octet.isdigit():
        return jsonify(ok=False, description="old_octet and new_octet must be plain numbers, e.g. 50 and 150"), 400

    with MANIFEST_LOCK:
        manifest = load_manifest(PROJECT_DIR)
        if not manifest:
            return jsonify(ok=False, description="No hosts in this project yet"), 400

        to_remap, skipped_no_match, skipped_collision = rr.compute_remap_plan(manifest, old_octet, new_octet)

        applied = False
        if to_remap and not dry_run:
            rr.apply_remap(PROJECT_DIR, manifest, to_remap)
            applied = True
            manifest = load_manifest(PROJECT_DIR)
            write_creds_files(PROJECT_DIR, manifest)
            write_targets_file(PROJECT_DIR, manifest)

    if applied:
        chown_project_dir(PROJECT_DIR)

    return jsonify(
        ok=True,
        applied=applied,
        to_remap=[{'old': o, 'new': n} for o, n in to_remap],
        skipped_collision=[{'old': o, 'new': n} for o, n in skipped_collision],
        skipped_no_match=skipped_no_match,
    )


@app.route('/api/host/<host>', methods=['DELETE'])
def api_delete_host(host):
    with MANIFEST_LOCK:
        manifest = load_manifest(PROJECT_DIR)
        if host not in manifest:
            return jsonify(ok=False, description=f"host {host} not found in project"), 404
        safe = manifest[host].get('safe') or host.replace('/', '_').replace('.', '-')
        del manifest[host]
        save_manifest(PROJECT_DIR, manifest)

    # Best-effort cleanup of associated files — a missing file is not an error.
    # This also removes the hand-edited Obsidian note; the confirm dialog on
    # the host page warns about this before the request is ever sent.
    for rel in [
        f"scans/html/{safe}.html",
        f"scans/nmap/{safe}.xml",
        f"scans/nmap/{safe}_udp.xml",
        f"scans/searchsploit/{safe}.txt",
        f"scans/creds/{safe}.txt",
        f"scans/ferox/{safe}.jsonl",
        f"scans/bloodhound/{safe}.zip",
        f"notes/{host}.md",
    ]:
        fpath = PROJECT_DIR / rel
        try:
            if fpath.exists():
                fpath.unlink()
        except Exception:
            pass

    # Refresh the static index/summary so the deleted host disappears from both.
    all_results = sorted(manifest.values(), key=lambda r: r['host'])
    rs.render_index(all_results, PROJECT_DIR, datetime.now())
    rs.render_obsidian_summary(all_results, PROJECT_DIR, datetime.now())

    # Drop the deleted host's creds out of the aggregated creds.txt too,
    # and the host itself out of targets.txt.
    write_creds_files(PROJECT_DIR, manifest)
    write_targets_file(PROJECT_DIR, manifest)
    chown_project_dir(PROJECT_DIR)

    return jsonify(ok=True, deleted=host)


def main():
    global PROJECT_DIR, BLOODHOUND_CE, PROXY_PORT
    p = argparse.ArgumentParser(description='Live dashboard + scan launcher for a recon_scan.py project')
    p.add_argument('project', help='Project directory (created automatically if it does not exist)')
    p.add_argument('--host', default='127.0.0.1', help='Bind address (use 0.0.0.0 to reach it from other devices)')
    p.add_argument('--port', type=int, default=5000)
    p.add_argument('--debug', action='store_true', default=False)
    p.add_argument('--proxy-port', type=int, default=9050,
                    help='SOCKS port to use via proxychains for targets with no direct route in the '
                         'kernel routing table (e.g. reachable only through an SSH -D / chisel-style '
                         'SOCKS tunnel, not a route-based one like ligolo-ng). Default: 9050. Every '
                         'scan checks routability per-target automatically.')
    p.add_argument('--bh-host', default=None,
                    help='BloodHound CE base URL (e.g. http://localhost:8080) — if set along with '
                         '--bh-key-id and --bh-key, BloodHound scan results are automatically '
                         'submitted for ingestion after each collection completes. Optional; '
                         'nothing changes if omitted.')
    p.add_argument('--bh-key-id', default=None,
                    help='BloodHound CE API Token ID (the public half of the pair — generate both '
                         'under Administration -> API Tokens in the BloodHound CE UI). Requires '
                         '--bh-host and --bh-key too.')
    p.add_argument('--bh-key', default=None,
                    help='BloodHound CE API Token Key (the secret half of the pair). Requires '
                         '--bh-host and --bh-key-id too.')
    args = p.parse_args()

    PROJECT_DIR = ensure_project_dirs(args.project)
    PROXY_PORT = args.proxy_port

    if not shutil.which('nmap'):
        warn("nmap not found — scans started from the dashboard will fail until it's installed")
    if not shutil.which('searchsploit'):
        warn("searchsploit not found — exploit lookups will be skipped for scans run from here")
    if not shutil.which('proxychains'):
        warn("proxychains not found — targets with no direct route will fail to scan until it's installed "
             "(only matters if you're pivoting through a SOCKS proxy)")
    if nmap_needs_sudo():
        warn("Not running as root and nmap doesn't have the raw-socket capability set — "
             "SYN/UDP scans need one or the other. Either run this with sudo, or (recommended) "
             "run ./setup_caps.sh once so nmap can do it unprivileged and you never need sudo again.")

    bh_flags_given = [args.bh_host, args.bh_key_id, args.bh_key]
    if all(bh_flags_given):
        BLOODHOUND_CE = {'host': args.bh_host.rstrip('/'), 'token_id': args.bh_key_id, 'token_key': args.bh_key}
        ok(f"BloodHound CE auto-submit enabled -> {B}{BLOODHOUND_CE['host']}{X}")
    elif any(bh_flags_given):
        warn("--bh-host, --bh-key-id, and --bh-key must all be set together for BloodHound CE "
             "auto-submit — only some were given, so it's disabled for this run.")

    n_hosts = len(load_manifest(PROJECT_DIR))
    write_creds_files(PROJECT_DIR, load_manifest(PROJECT_DIR))
    write_targets_file(PROJECT_DIR, load_manifest(PROJECT_DIR))
    chown_project_dir(PROJECT_DIR)
    ok(f"Serving {B}{PROJECT_DIR}{X} ({n_hosts} host(s)) at {C}http://{args.host}:{args.port}/{X}")
    if args.host == '0.0.0.0':
        warn("Bound to 0.0.0.0 — reachable from anywhere on your network. No auth is implemented.")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == '__main__':
    main()
