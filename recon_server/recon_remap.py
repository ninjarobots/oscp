#!/usr/bin/env python3
"""
recon_remap.py — re-key a project when a PEN-200 lab restart changes the
third octet of every host's IP (e.g. 192.168.50.x -> 192.168.150.x).

Migrates the manifest, renames every associated file (notes, html, nmap
XML, searchsploit output), and rewrites literal IP references inside the
note/html content — so all your hand-written notes, credentials, and
flags survive the octet change intact.

Usage:
    python3 recon_remap.py <project_dir> <old_octet> <new_octet> [--dry-run]

Example:
    # Lab restarted, subnet went from 192.168.50.x to 192.168.150.x
    python3 recon_remap.py ~/relia-lab 50 150

Only hosts whose third octet matches <old_octet> are touched. Hosts that
don't match (different subnet already, or a hostname rather than a raw
IP) are left alone and reported at the end.
"""
import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

try:
    from recon_common import load_manifest, save_manifest
    import recon_scan as rs
except ImportError as e:
    print(f"[-] Could not import recon_common / recon_scan.py: {e}")
    print("    Keep recon_remap.py in the same directory as the rest of the project.")
    sys.exit(1)

IPV4_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')

ASSOCIATED_FILES = [
    ('scans/html/{safe}.html', True),    # (path template, contains literal IP text worth rewriting)
    ('scans/nmap/{safe}.xml', False),
    ('scans/nmap/{safe}_udp.xml', False),
    ('scans/searchsploit/{safe}.txt', False),
    ('scans/creds/{safe}.txt', False),
    ('scans/ferox/{safe}.jsonl', False),
    ('scans/bloodhound/{safe}.zip', False),
    ('notes/{host}.md', True),
]


def safe_name(host: str) -> str:
    return host.replace('/', '_').replace('.', '-')


def compute_new_host(host: str, old_octet: str, new_octet: str):
    m = IPV4_RE.match(host)
    if not m:
        return None  # not a plain IPv4 — leave untouched
    o1, o2, o3, o4 = m.groups()
    if o3 != old_octet:
        return None  # doesn't match the octet we're remapping
    return f"{o1}.{o2}.{new_octet}.{o4}"


def compute_remap_plan(manifest: dict, old_octet: str, new_octet: str):
    """Pure planning step — no filesystem changes. Returns
    (to_remap, skipped_no_match, skipped_collision)."""
    to_remap = []
    skipped_no_match = []
    skipped_collision = []

    for host in manifest:
        new_host = compute_new_host(host, old_octet, new_octet)
        if new_host is None:
            skipped_no_match.append(host)
            continue
        if new_host in manifest and new_host != host:
            skipped_collision.append((host, new_host))
            continue
        to_remap.append((host, new_host))

    return to_remap, skipped_no_match, skipped_collision


def apply_remap(project_dir: Path, manifest: dict, to_remap: list):
    """Executes a remap plan: renames files, rewrites IP text, saves the
    manifest, and regenerates index.html / the Obsidian summary."""
    new_manifest = dict(manifest)

    for old_host, new_host in to_remap:
        record = dict(new_manifest.pop(old_host))
        old_safe = record.get('safe') or safe_name(old_host)
        new_safe = safe_name(new_host)

        for template, has_ip_text in ASSOCIATED_FILES:
            old_path = project_dir / template.format(safe=old_safe, host=old_host)
            new_path = project_dir / template.format(safe=new_safe, host=new_host)
            if not old_path.exists():
                continue
            if has_ip_text:
                try:
                    text = old_path.read_text(encoding='utf-8', errors='ignore')
                    text = text.replace(old_host, new_host)
                    old_path.write_text(text, encoding='utf-8')
                except Exception:
                    pass  # best-effort — file still gets renamed even if the text rewrite fails
            new_path.parent.mkdir(parents=True, exist_ok=True)
            old_path.rename(new_path)

        record['host'] = new_host
        record['safe'] = new_safe
        new_manifest[new_host] = record

    save_manifest(project_dir, new_manifest)

    all_results = sorted(new_manifest.values(), key=lambda r: r['host'])
    rs.render_index(all_results, project_dir, datetime.now())
    rs.render_obsidian_summary(all_results, project_dir, datetime.now())

    return new_manifest


def remap_project(project_dir: Path, old_octet: str, new_octet: str, dry_run: bool):
    """CLI entry point — plans, prints a human-readable summary, and (unless
    dry_run) applies the plan via apply_remap()."""
    manifest = load_manifest(project_dir)
    if not manifest:
        print(f"[-] No manifest found at {project_dir}/scans/.manifest.json — nothing to remap")
        return

    to_remap, skipped_no_match, skipped_collision = compute_remap_plan(manifest, old_octet, new_octet)

    if not to_remap:
        if skipped_collision:
            print(f"[-] {len(skipped_collision)} host(s) matched octet '{old_octet}' but were skipped "
                  f"— target IP already exists in the manifest:")
            for old_host, new_host in skipped_collision:
                print(f"    {old_host} -> {new_host} (already present, not touched)")
        else:
            print(f"[-] No hosts matched third octet '{old_octet}' — nothing to do")
        if skipped_no_match:
            print(f"    ({len(skipped_no_match)} other host(s) left untouched, e.g. {skipped_no_match[:3]})")
        return

    print(f"[+] {len(to_remap)} host(s) will be remapped:")
    for old_host, new_host in to_remap:
        print(f"    {old_host}  ->  {new_host}")

    if skipped_collision:
        print(f"\n[!] {len(skipped_collision)} host(s) skipped — target IP already exists in manifest:")
        for old_host, new_host in skipped_collision:
            print(f"    {old_host} -> {new_host} (already present, not touched)")

    if dry_run:
        print("\n[dry-run] No changes made.")
        return

    apply_remap(project_dir, manifest, to_remap)

    print(f"\n[+] Remap complete. index.html and notes/_scan_summary.md regenerated.")
    if skipped_no_match:
        print(f"[i] {len(skipped_no_match)} host(s) didn't match octet '{old_octet}' and were left as-is.")


def parse_args():
    p = argparse.ArgumentParser(description='Remap a project after a lab restart changes the subnet octet')
    p.add_argument('project', help='Project directory')
    p.add_argument('old_octet', help='Current (old) third octet, e.g. 50')
    p.add_argument('new_octet', help='New third octet, e.g. 150')
    p.add_argument('--dry-run', action='store_true', help='Show what would change without touching anything')
    return p.parse_args()


def main():
    args = parse_args()
    project_dir = Path(args.project)
    if not project_dir.exists():
        print(f"[-] Project directory not found: {project_dir}", file=sys.stderr)
        sys.exit(1)
    if not args.old_octet.isdigit() or not args.new_octet.isdigit():
        print("[-] old_octet and new_octet must be plain numbers, e.g. 50 150", file=sys.stderr)
        sys.exit(1)

    remap_project(project_dir, args.old_octet, args.new_octet, args.dry_run)


if __name__ == '__main__':
    main()
