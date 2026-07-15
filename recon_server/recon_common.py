#!/usr/bin/env python3
"""
recon_common.py — shared helpers for recon_scan.py and recon_server.py.

Keep this file in the same directory as both scripts. It owns the single
source of truth for:
  - the project manifest (scans/.manifest.json) — scan results + Local/Proof
    flag state, so a rescan never clobbers flags you've already set
  - shared CSS so the static snapshot and the live Flask dashboard look
    identical
  - small HTML-rendering helpers used by both
"""
import html
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# ── ANSI colors ───────────────────────────────────────────────────────────────
R = '\033[0;31m'; G = '\033[0;32m'; Y = '\033[1;33m'
C = '\033[0;36m'; B = '\033[1m';    X = '\033[0m'

def log(m):  print(f"{C}[*]{X} {m}")
def ok(m):   print(f"{G}[+]{X} {m}")
def warn(m): print(f"{Y}[!]{X} {m}")
def err(m):
    print(f"{R}[-]{X} {m}")
    sys.exit(1)

def h(s):
    return html.escape(str(s))

# ── Ownership fixup for sudo runs ───────────────────────────────────────────
# nmap's SYN/UDP scans need root, so this whole project typically runs under
# sudo — which means every file it writes ends up owned by root, and the
# person then can't edit/delete their own notes without sudo. sudo sets
# SUDO_UID/SUDO_GID to the original (pre-sudo) user, so we can chown things
# back automatically. No-op if not running as root under sudo (e.g. rootless
# setups, or testing without sudo).
def _invoking_user_ids():
    if os.geteuid() != 0:
        return None
    sudo_uid, sudo_gid = os.environ.get('SUDO_UID'), os.environ.get('SUDO_GID')
    if sudo_uid is None or sudo_gid is None:
        return None
    try:
        return int(sudo_uid), int(sudo_gid)
    except ValueError:
        return None

def chown_project_dir(out_dir) -> None:
    """Recursively chown out_dir back to the invoking (pre-sudo) user. Safe
    to call often — skips entirely if not applicable, and a failed chown on
    an individual file (e.g. a permissions edge case) doesn't abort the rest."""
    ids = _invoking_user_ids()
    if ids is None:
        return
    uid, gid = ids
    out_dir = Path(out_dir)
    try:
        os.chown(out_dir, uid, gid)
    except OSError:
        pass
    for root, dirs, files in os.walk(out_dir):
        for name in dirs + files:
            try:
                os.chown(os.path.join(root, name), uid, gid)
            except OSError:
                pass

# ── Manifest ──────────────────────────────────────────────────────────────────
# This JSON file is the single source of truth for both scripts. recon_scan.py
# writes scan-derived fields (ports, exploits, os, etc). recon_server.py writes
# 'local' / 'proof' flag state. Neither ever wholesale-overwrites the other's
# fields — see merge_scan_results() below.
def manifest_path(out_dir) -> Path:
    return Path(out_dir) / 'scans' / '.manifest.json'

def ensure_project_dirs(out_dir) -> Path:
    """Create the project's scans/notes layout. Safe to call on an existing project."""
    out_dir = Path(out_dir)
    for d in ['scans/nmap', 'scans/searchsploit', 'scans/html', 'notes']:
        (out_dir / d).mkdir(parents=True, exist_ok=True)
    return out_dir

def load_manifest(out_dir) -> dict:
    """Returns {host: record}. Empty dict if no manifest exists yet."""
    mpath = manifest_path(out_dir)
    if not mpath.exists():
        return {}
    try:
        data = json.loads(mpath.read_text(encoding='utf-8'))
        return {r['host']: r for r in data}
    except Exception:
        return {}

def save_manifest(out_dir, results_by_host: dict):
    mpath = manifest_path(out_dir)
    mpath.parent.mkdir(parents=True, exist_ok=True)
    mpath.write_text(json.dumps(list(results_by_host.values()), indent=2), encoding='utf-8')

def merge_scan_results(existing: dict, new_results: list) -> dict:
    """
    Merge freshly-scanned host results into the existing manifest.
    Scan-derived fields (ports/exploits/os/services/etc) come from the new
    scan. 'local'/'proof' flags (and the timestamp of when each was set),
    'credentials', and 'ferox' results are only ever set from the
    dashboard, so they are always carried forward from the existing record.
    """
    merged = dict(existing)
    for r in new_results:
        r = dict(r)
        old = merged.get(r['host'], {})
        r['local'] = old.get('local', False)
        r['proof'] = old.get('proof', False)
        r['local_updated_at'] = old.get('local_updated_at')
        r['proof_updated_at'] = old.get('proof_updated_at')
        r['credentials'] = old.get('credentials', [])
        r['ferox'] = old.get('ferox', [])
        r['ferox_target_url'] = old.get('ferox_target_url')
        r['ferox_scanned_at'] = old.get('ferox_scanned_at')
        merged[r['host']] = r
    return merged

def _append_note_log_entry(out_dir, host: str, marker: str, intro: str, entry: str) -> None:
    """
    Shared append-only note logger. Inserts `entry` (one or more lines,
    already formatted) into notes/<host>.md under a `## <marker>` heading,
    creating the section with `intro` text on first use. New entries are
    inserted right after the intro line each time, so the log reads
    newest-first without needing to re-read/re-order older entries.

    No-op if the note doesn't exist (e.g. it was deleted) — logging into a
    missing file would just silently create a bare note with none of the
    usual structure.
    """
    out_dir = Path(out_dir)
    note_path = out_dir / 'notes' / f"{host}.md"
    if not note_path.exists():
        return

    text = note_path.read_text(encoding='utf-8', errors='ignore')

    if marker in text:
        idx = text.index(marker)
        insert_at = text.find('\n', text.find('\n', idx) + 1) + 1
        if insert_at <= 0:
            text = text.rstrip('\n') + f"\n{entry}\n"
        else:
            text = text[:insert_at] + entry + '\n' + text[insert_at:]
    else:
        text = text.rstrip('\n') + f"\n\n{marker}\n{intro}\n{entry}\n"

    note_path.write_text(text, encoding='utf-8')


def append_cred_to_note(out_dir, host: str, cred: dict) -> None:
    """
    Log a newly-added credential into notes/<host>.md as a timestamped,
    append-only entry. This is a history log, not a live mirror of current
    status — the manifest stays the single source of truth for what a
    credential's status is *now* (see the Credentials card / recon_report.py),
    so this can't drift out of sync the way a synced table would.
    """
    ts = datetime.now().strftime('%Y-%m-%d %H:%M')
    secret_disp = f"`{cred.get('secret','')}`"
    bits = [f"`{ts}`", f"**{cred.get('username','')}**", ':', secret_disp, f"({cred.get('type','password')})"]
    if cred.get('service'):
        bits.append(f"— {cred['service']}")
    if cred.get('status'):
        bits.append(f"— status: {cred['status']}")
    if cred.get('notes'):
        bits.append(f"— {cred['notes']}")
    entry = '- ' + ' '.join(bits)

    _append_note_log_entry(
        out_dir, host, '## Credential Log',
        "_Auto-logged whenever a credential is added via the dashboard. "
        "This is a history, not the current source of truth — see the "
        "Credentials card on this host's page (or `recon_report.py`) for "
        "up-to-date status._",
        entry,
    )


def write_creds_files(out_dir, manifest: dict) -> None:
    """
    Mirror every tracked credential out to plain-text 'user:secret' files —
    the same format spray-all.sh expects — so creds added via the dashboard
    are immediately usable with nxc, no manual copy-paste needed.

        <out_dir>/creds.txt               all creds, deduped, across every host
        <out_dir>/scans/creds/<safe>.txt  just this host's creds

    Call this after any add/edit/delete of a credential, and once at
    server startup so pre-existing manifest creds get files too.
    """
    out_dir = Path(out_dir)
    creds_dir = out_dir / 'scans' / 'creds'
    creds_dir.mkdir(parents=True, exist_ok=True)

    seen = set()
    global_lines = []

    for host, r in manifest.items():
        creds = r.get('credentials', [])
        safe = r.get('safe') or host
        host_file = creds_dir / f"{safe}.txt"

        if creds:
            host_lines = [f"{c['username']}:{c['secret']}" for c in creds]
            host_file.write_text('\n'.join(host_lines) + '\n', encoding='utf-8')
        elif host_file.exists():
            host_file.unlink()

        for c in creds:
            pair = f"{c['username']}:{c['secret']}"
            if pair not in seen:
                seen.add(pair)
                global_lines.append(pair)

    global_path = out_dir / 'creds.txt'
    if global_lines:
        global_path.write_text('\n'.join(global_lines) + '\n', encoding='utf-8')
    elif global_path.exists():
        global_path.unlink()


# ── Exploit classification / service badges ───────────────────────────────────
def classify(title):
    t = title.lower()
    if any(x in t for x in ['remote code', 'rce', 'command execution', 'code exec', 'backdoor']):
        return 'RCE', 'badge-red'
    if any(x in t for x in ['buffer overflow', 'stack overflow', 'heap overflow']):
        return 'BOF', 'badge-red'
    if any(x in t for x in ['privilege escalation', 'privesc', 'local privilege']):
        return 'LPE', 'badge-orange'
    if any(x in t for x in ['path traversal', 'traversal', 'path disclos']):
        return 'Trav', 'badge-orange'
    if any(x in t for x in ['sql injection', 'sqli']):
        return 'SQLi', 'badge-orange'
    if any(x in t for x in ['xss', 'cross-site']):
        return 'XSS', 'badge-cyan'
    if any(x in t for x in ['denial', ' dos ', 'crash']):
        return 'DoS', 'badge-muted'
    if any(x in t for x in ['bypass', 'auth bypass']):
        return 'Bypass', 'badge-orange'
    return 'INFO', 'badge-muted'

def svc_badge(name):
    n = name.lower()
    if n in ('http', 'https', 'http-proxy', 'http-alt'):
        return f"<span class='badge badge-cyan'>{h(name)}</span>"
    if n in ('smb', 'microsoft-ds', 'netbios-ssn', 'msrpc'):
        return f"<span class='badge badge-orange'>{h(name)}</span>"
    if n in ('ssh', 'telnet', 'ftp'):
        return f"<span class='badge badge-green'>{h(name)}</span>"
    if n in ('rdp', 'ms-wbt-server'):
        return f"<span class='badge badge-purple'>{h(name)}</span>"
    if n in ('ldap', 'ldaps', 'kerberos-sec', 'kpasswd5', 'msft-gc', 'msft-gc-ssl'):
        return f"<span class='badge badge-orange'>{h(name)}</span>"
    if name:
        return f"<span class='svc-name'>{h(name)}</span>"
    return "<span style='color:var(--muted)'>unknown</span>"

# ── Flag chips (Local / Proof) ─────────────────────────────────────────────────
def render_flag_chips(host, local, proof, interactive):
    """
    Renders the Local/Proof status chips for a host card.
    interactive=True  -> Flask dashboard: clickable, POSTs to /api/status
    interactive=False -> static snapshot: read-only (reflects manifest as of
                          the last recon_scan.py run; toggle from the dashboard)
    """
    if interactive:
        local_html = (
            f"<label class='flag-chip{' on' if local else ''}' onclick='event.stopPropagation()'>"
            f"<input type='checkbox' {'checked' if local else ''} "
            f"onclick=\"event.stopPropagation(); setFlag('{h(host)}','local',this.checked,this)\">Local</label>"
        )
        proof_html = (
            f"<label class='flag-chip proof{' on' if proof else ''}' onclick='event.stopPropagation()'>"
            f"<input type='checkbox' {'checked' if proof else ''} "
            f"onclick=\"event.stopPropagation(); setFlag('{h(host)}','proof',this.checked,this)\">Proof</label>"
        )
    else:
        local_html = f"<span class='flag-chip static{' on' if local else ''}'>{'&#9745;' if local else '&#9744;'} Local</span>"
        proof_html = f"<span class='flag-chip proof static{' on' if proof else ''}'>{'&#9745;' if proof else '&#9744;'} Proof</span>"
    return f"<div class='flag-row'>{local_html}{proof_html}</div>"

# ── Shared CSS ──────────────────────────────────────────────────────────────
CSS = """
<style>
  :root {
    --bg:        #0d1117;
    --surface:   #161b22;
    --surface2:  #1c2128;
    --border:    #30363d;
    --green:     #3fb950;
    --cyan:      #58a6ff;
    --orange:    #f0883e;
    --red:       #f85149;
    --purple:    #bc8cff;
    --text:      #e6edf3;
    --muted:     #8b949e;
    --font-mono: 'Cascadia Code', 'Fira Code', 'JetBrains Mono', monospace;
    --font-ui:   'Segoe UI', system-ui, sans-serif;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font-ui); font-size: 14px; line-height: 1.6; min-height: 100vh; }
  a { color: var(--cyan); text-decoration: none; }
  a:hover { text-decoration: underline; }
  header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 12px 24px; display: flex; align-items: center; gap: 16px; }
  header .logo { font-family: var(--font-mono); font-size: 18px; color: var(--green); letter-spacing: -0.5px; font-weight: 700; }
  header nav { margin-left: auto; display: flex; gap: 16px; align-items: center; }
  header nav a { color: var(--muted); font-size: 13px; }
  header nav a:hover { color: var(--text); }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  h1 { font-size: 22px; font-weight: 600; margin-bottom: 4px; }
  h2 { font-size: 15px; font-weight: 600; color: var(--cyan); margin: 0; }
  .subtitle { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 16px; overflow: hidden; }
  .card-header { padding: 12px 16px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; }
  .card-body { padding: 16px; }
  .badge { display: inline-block; padding: 2px 7px; border-radius: 12px; font-size: 11px; font-weight: 600; font-family: var(--font-mono); white-space: nowrap; }
  .badge-green  { background: rgba(63,185,80,.15);  color: var(--green);  border: 1px solid rgba(63,185,80,.3); }
  .badge-orange { background: rgba(240,136,62,.15); color: var(--orange); border: 1px solid rgba(240,136,62,.3); }
  .badge-red    { background: rgba(248,81,73,.15);  color: var(--red);    border: 1px solid rgba(248,81,73,.3); }
  .badge-cyan   { background: rgba(88,166,255,.15); color: var(--cyan);   border: 1px solid rgba(88,166,255,.3); }
  .badge-purple { background: rgba(188,140,255,.15);color: var(--purple); border: 1px solid rgba(188,140,255,.3); }
  .badge-muted  { background: rgba(139,148,158,.1); color: var(--muted);  border: 1px solid rgba(139,148,158,.2); }
  .meta-table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: var(--font-mono); }
  .meta-table td { padding: 5px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  .meta-table td:first-child { color: var(--muted); width: 140px; white-space: nowrap; }
  .meta-table tr:last-child td { border-bottom: none; }
  .port-table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: var(--font-mono); }
  .port-table th { text-align: left; padding: 6px 10px; color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.4px; border-bottom: 1px solid var(--border); }
  .port-table td { padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  .port-table tr:last-child > td { border-bottom: none; }
  .port-table tr:hover > td { background: rgba(255,255,255,.02); }
  .port-num { color: var(--orange); font-weight: 600; }
  .svc-name { color: var(--green); }
  .script-block { margin-top: 6px; }
  .script-id { color: var(--purple); font-size: 11px; margin-bottom: 3px; }
  .script-output { background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 8px 10px; font-size: 11px; color: var(--muted); font-family: var(--font-mono); white-space: pre-wrap; word-break: break-word; line-height: 1.5; max-height: 200px; overflow-y: auto; }
  .exploit-row { display: grid; grid-template-columns: 80px 1fr; gap: 10px; align-items: baseline; padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 12px; }
  .exploit-row:last-child { border-bottom: none; }
  .exploit-id { font-family: var(--font-mono); color: var(--muted); font-size: 11px; }
  .exploit-title { color: var(--text); }
  .exploit-path { font-family: var(--font-mono); font-size: 11px; color: var(--muted); margin-top: 2px; }
  .query-group { margin-bottom: 16px; }
  .query-label { font-size: 11px; color: var(--muted); font-family: var(--font-mono); margin-bottom: 6px; padding-bottom: 4px; border-bottom: 1px dashed var(--border); }
  .stat-row { display: flex; gap: 24px; margin-bottom: 20px; flex-wrap: wrap; }
  .stat .val { font-size: 28px; font-family: var(--font-mono); font-weight: 700; color: var(--green); }
  .stat .lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px; }
  .target-card { position: relative; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 16px; transition: border-color .15s; }
  .target-card:hover { border-color: var(--cyan); }
  .target-ip { font-family: var(--font-mono); font-size: 16px; font-weight: 700; margin-bottom: 8px; }
  .target-meta { font-size: 12px; color: var(--muted); display: flex; gap: 12px; flex-wrap: wrap; }
  .exploit-count { margin-top: 10px; font-size: 12px; padding: 4px 8px; border-radius: 4px; display: inline-block; }
  .has-exploits { background: rgba(248,81,73,.1); color: var(--red); border: 1px solid rgba(248,81,73,.3); }
  .no-exploits  { background: rgba(139,148,158,.08); color: var(--muted); }
  .search-bar { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 8px 14px; color: var(--text); font-family: var(--font-mono); font-size: 13px; width: 100%; max-width: 400px; margin-bottom: 20px; outline: none; }
  .search-bar:focus { border-color: var(--cyan); }
  footer { border-top: 1px solid var(--border); padding: 16px 24px; text-align: center; font-size: 12px; color: var(--muted); margin-top: 48px; }
  .hidden { display: none; }
  .empty-msg { color: var(--muted); font-size: 13px; padding: 4px 0; }

  /* Local/Proof flag chips */
  .flag-row { display: flex; gap: 8px; margin-top: 12px; }
  .flag-chip { display: flex; align-items: center; gap: 5px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .4px; padding: 4px 9px; border-radius: 4px; background: rgba(139,148,158,.08); color: var(--muted); border: 1px solid rgba(139,148,158,.2); cursor: pointer; user-select: none; }
  .flag-chip input { accent-color: var(--green); cursor: pointer; width: 13px; height: 13px; }
  .flag-chip.static { cursor: default; }
  .flag-chip.on { background: rgba(63,185,80,.12); color: var(--green); border-color: rgba(63,185,80,.35); }
  .flag-chip.proof.on { background: rgba(188,140,255,.12); color: var(--purple); border-color: rgba(188,140,255,.35); }

  /* Live dashboard extras */
  .toolbar-row { display: flex; align-items: center; gap: 20px; flex-wrap: wrap; margin-bottom: 20px; }
  .progress-wrap { flex: 1; min-width: 220px; max-width: 360px; }
  .progress-label { font-size: 11px; color: var(--muted); display: flex; justify-content: space-between; margin-bottom: 5px; font-family: var(--font-mono); }
  .progress-track { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; height: 8px; overflow: hidden; display: flex; }
  .progress-fill-local { background: var(--green); height: 100%; }
  .progress-fill-proof { background: var(--purple); height: 100%; }
  .hide-completed-toggle { font-size: 12px; color: var(--muted); display: flex; align-items: center; gap: 6px; cursor: pointer; user-select: none; white-space: nowrap; }
  .hide-completed-toggle input { accent-color: var(--purple); cursor: pointer; }
  .grid.hide-done .target-card.fully-owned { display: none; }
  .live-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); display: inline-block; box-shadow: 0 0 6px var(--green); }
  .save-toast { position: fixed; bottom: 20px; right: 20px; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 10px 16px; font-size: 12px; color: var(--muted); opacity: 0; transform: translateY(8px); transition: opacity .2s, transform .2s; pointer-events: none; }
  .save-toast.show { opacity: 1; transform: translateY(0); }
</style>
"""
