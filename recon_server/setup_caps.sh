#!/usr/bin/env bash
# setup_caps.sh — grant nmap the raw-socket capabilities it needs
# (CAP_NET_RAW, CAP_NET_ADMIN) directly on the binary, so recon_scan.py /
# recon_server.py can run as your normal user instead of needing sudo for
# the whole process.
#
# Only nmap needs this — nxc, feroxbuster, bloodhound-python, and
# proxychains are all regular userspace network clients (normal
# connect()/socket() calls) and never need elevated privileges. It's
# specifically nmap's SYN scan and raw packet crafting (UDP scan, OS
# detection) that require CAP_NET_RAW.
#
# This script itself needs to run as root ONCE (setting file capabilities
# is a privileged operation) — after that, nmap runs unprivileged and
# recon_scan.py/recon_server.py never need sudo again.
#
# Usage: sudo ./setup_caps.sh

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[-] This script needs to run as root (it's setting file capabilities on a binary)." >&2
  echo "    Re-run it with sudo: sudo ./setup_caps.sh" >&2
  exit 1
fi

if ! command -v setcap &>/dev/null; then
  echo "[-] setcap not found. Install it first: sudo apt install libcap2-bin" >&2
  exit 1
fi

NMAP_PATH="$(command -v nmap || true)"
if [[ -z "$NMAP_PATH" ]]; then
  echo "[-] nmap not found in PATH. Install it first: sudo apt install nmap" >&2
  exit 1
fi

# Capabilities are tied to the actual file, not a symlink pointing at it —
# setting them on a symlink silently does nothing useful, so resolve to
# the real binary first.
REAL_PATH="$(readlink -f "$NMAP_PATH")"

echo "[*] nmap found at: $NMAP_PATH -> $REAL_PATH"
echo "[*] Granting cap_net_raw,cap_net_admin+eip..."
setcap cap_net_raw,cap_net_admin+eip "$REAL_PATH"

echo "[*] Verifying..."
if getcap "$REAL_PATH" | grep -q cap_net_raw; then
  echo "[+] Done. nmap can now run SYN/UDP scans without sudo."
  echo "[+] You no longer need to run recon_scan.py/recon_server.py with sudo — both"
  echo "    check for this automatically and will fall back to sudo only if it's missing."
else
  echo "[-] setcap ran without error but the capability doesn't appear to be set." >&2
  echo "    Check manually with: getcap $REAL_PATH" >&2
  exit 1
fi

echo
echo "Note: if nmap is ever reinstalled or updated (apt upgrade nmap), the package"
echo "manager replaces the binary and this capability gets reset — just re-run this"
echo "script after any nmap upgrade."
