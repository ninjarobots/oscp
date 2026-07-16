#!/usr/bin/env python3
"""
recon_report.py — build a single consolidated report from a recon_scan.py project.

Pulls two sources of truth and merges them:
  - scans/.manifest.json  (host metadata, Local/Proof flags, credentials —
    all authoritative/live data, never hand-edited)
  - notes/<host>.md       (your hand-written narrative: attack path,
    foothold, privesc, flags, etc.)

Usage:
    python3 recon_report.py <project_dir> [-o OUTPUT.md] [--all] [--full]

By default only hosts flagged Local or Proof on the dashboard are included
(i.e. "finished" boxes) — use --all to include every scanned host regardless
of flag state, e.g. for a full recon dump rather than an exam report.

By default each host section is curated (Timeline, Open Ports, Attack Notes,
Flags) to keep the report readable — use --full to include every section
from the note verbatim (System/Network Info, Searchsploit, NSE output, etc).
"""
import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

try:
    from recon_common import load_manifest, h
except ImportError:
    print("[-] recon_common.py not found. Keep it in the same directory as recon_report.py")
    sys.exit(1)

# Section order for the default curated report. Sections not present in a
# given note are simply skipped — this list is a preference order, not a
# requirement.
CURATED_SECTIONS = ['Timeline', 'Network Access', 'Open Ports', 'Attack Notes', 'Credential Log', 'Flags']

HEADING_RE = re.compile(r'(?m)^## (.+)$')


def parse_note_sections(text: str) -> dict:
    """Split a host note into {heading: body} for every top-level '## ' section.
    Nested '### ' subsections stay embedded in their parent's body untouched."""
    parts = HEADING_RE.split(text)
    sections = {}
    it = iter(parts[1:])  # parts[0] is frontmatter/title before the first '## '
    for heading, body in zip(it, it):
        sections[heading.strip()] = body.strip('\n')
    return sections


def load_note(project_dir: Path, host: str) -> str:
    note_path = project_dir / 'notes' / f"{host}.md"
    if not note_path.exists():
        return ''
    return note_path.read_text(encoding='utf-8', errors='ignore')


def host_status_label(r: dict) -> str:
    local, proof = bool(r.get('local')), bool(r.get('proof'))
    # proof.txt means root/SYSTEM — that's full ownership on its own. Plenty
    # of boxes (most AD ones, some web-app boxes) go straight there with no
    # separate low-priv shell along the way, so local.txt never gets set —
    # requiring both flags would wrongly demote those to "Proof only".
    if proof:
        return 'Fully owned'
    if local:
        return 'Local only'
    return 'Not flagged'


def access_info(r: dict):
    """
    (sort_key, display_label) for when access was actually gained on this
    host, so the report can be ordered the way the engagement really went
    rather than alphabetically by IP.

    Uses the Local flag's timestamp (foothold landed) as the primary signal
    — that's the moment "access was gained" in the sense most people mean
    it — falling back to the Proof timestamp (flag captured) if Local was
    never explicitly checked. Both are stamped automatically by the
    dashboard the moment you tick the box, so this needs no manual dates.
    Hosts with neither (only reachable via --all) sort last, since there's
    no access-gained event to order them by.
    """
    for field in ('local_updated_at', 'proof_updated_at'):
        ts = r.get(field)
        if ts:
            try:
                dt = datetime.fromisoformat(ts)
                return dt, dt.strftime('%Y-%m-%d %H:%M')
            except (TypeError, ValueError):
                pass
    return datetime.max, '—'


def build_report(project_dir: Path, include_all: bool, full_sections: bool) -> str:
    manifest = load_manifest(project_dir)
    all_results = sorted(manifest.values(), key=lambda r: access_info(r)[0])

    if include_all:
        results = all_results
    else:
        results = [r for r in all_results if r.get('local') or r.get('proof')]

    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    lines = []

    # ── Title / summary ──────────────────────────────────────────────────────
    lines.append(f"# Final Report — {project_dir.name}")
    lines.append('')
    lines.append(f"Generated: {now}")
    lines.append('')
    if not include_all:
        lines.append("_Includes hosts flagged Local or Proof only. Run with `--all` to include every scanned host._")
        lines.append('')

    total_hosts = len(results)
    fully_owned = sum(1 for r in results if r.get('proof'))
    total_creds = sum(len(r.get('credentials', [])) for r in results)

    lines.append('## Executive Summary')
    lines.append('')
    lines.append(f"- **Hosts included:** {total_hosts}")
    lines.append(f"- **Fully owned (Proof captured):** {fully_owned}")
    lines.append(f"- **Credentials recorded:** {total_creds}")
    lines.append('')
    lines.append('_Ordered by when access was gained (Local flag timestamp, falling back to Proof) — not alphabetically._')
    lines.append('')

    lines.append('| # | Host | Hostname | OS | Status | Access Gained | Exploit Hits |')
    lines.append('|---|------|----------|-----|--------|----------------|--------------|')
    for i, r in enumerate(results, 1):
        os_short = (r.get('os') or '').split('(')[0].strip() or '—'
        hn = r.get('hostname') or '—'
        _, access_label = access_info(r)
        lines.append(f"| {i} | {r['host']} | {hn} | {os_short} | {host_status_label(r)} | {access_label} | {r.get('exploits', 0)} |")
    lines.append('')

    # ── Credentials appendix ─────────────────────────────────────────────────
    # Pulled fresh from the manifest (the live-tracked source) rather than
    # from any per-host note, so this can never drift out of sync.
    lines.append('## Credentials Appendix')
    lines.append('')
    any_creds = False
    lines.append('| Host | Username | Secret | Type | Service | Status | Notes |')
    lines.append('|------|----------|--------|------|---------|--------|-------|')
    for r in results:
        for c in r.get('credentials', []):
            any_creds = True
            lines.append(
                f"| {r['host']} | {c.get('username','')} | `{c.get('secret','')}` | "
                f"{c.get('type','')} | {c.get('service','')} | {c.get('status','')} | {c.get('notes','')} |"
            )
    if not any_creds:
        lines.append('| — | — | — | — | — | — | — |')
    lines.append('')

    # ── Per-host sections ─────────────────────────────────────────────────────
    lines.append('## Host Details')
    lines.append('')
    for i, r in enumerate(results, 1):
        host = r['host']
        lines.append(f"### {i}. {host}" + (f" — `{r['hostname']}`" if r.get('hostname') else ''))
        lines.append('')
        os_str = r.get('os') or 'unknown'
        lines.append(f"**OS:** {os_str}  ")
        lines.append(f"**Status:** {host_status_label(r)}  ")
        lines.append(f"**Open ports:** {r.get('ports', 0)} &nbsp;&middot;&nbsp; **Exploit hits:** {r.get('exploits', 0)}")
        lines.append('')

        note_text = load_note(project_dir, host)
        if not note_text:
            lines.append('_No note found for this host._')
            lines.append('')
            continue

        sections = parse_note_sections(note_text)
        wanted = list(sections.keys()) if full_sections else [s for s in CURATED_SECTIONS if s in sections]

        if not wanted:
            lines.append('_Note exists but has no recognizable sections._')
            lines.append('')
            continue

        for sec_name in wanted:
            lines.append(f"#### {sec_name}")
            lines.append('')
            lines.append(sections[sec_name])
            lines.append('')

    return '\n'.join(lines)


def parse_args():
    p = argparse.ArgumentParser(description='Build a consolidated report from a recon_scan.py project')
    p.add_argument('project', help='Project directory (same one passed to recon_scan.py / recon_server.py)')
    p.add_argument('-o', '--output', help='Output path (default: <project>/FINAL_REPORT.md)')
    p.add_argument('--all', action='store_true', help='Include every scanned host, not just Local/Proof-flagged ones')
    p.add_argument('--full', action='store_true', help='Include every section from each note, not just the curated set')
    return p.parse_args()


def main():
    args = parse_args()
    project_dir = Path(args.project)
    if not project_dir.exists():
        print(f"[-] Project directory not found: {project_dir}", file=sys.stderr)
        sys.exit(1)

    report = build_report(project_dir, include_all=args.all, full_sections=args.full)

    out_path = Path(args.output) if args.output else project_dir / 'FINAL_REPORT.md'
    out_path.write_text(report, encoding='utf-8')
    print(f"[+] Report written: {out_path}")


if __name__ == '__main__':
    main()
