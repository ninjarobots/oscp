#!/usr/bin/env bash
#
# install.sh — pwndex installer
#
# Installs dependencies via apt and copies pwndex to /usr/local/bin.
# Designed for Kali Linux. Run as root or with sudo.
#
# Usage:
#   sudo ./install.sh
#   sudo ./install.sh --uninstall

set -euo pipefail

INSTALL_PATH="/usr/local/bin/pwndex"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$SCRIPT_DIR/pwndex"

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'; CYAN='\033[96m'; RESET='\033[0m'; BOLD='\033[1m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
ok()      { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
die()     { echo -e "${RED}[-]${RESET} $*" >&2; exit 1; }

# ── Privilege check ───────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    die "Run as root: sudo ./install.sh"
fi

# ── Uninstall ─────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--uninstall" ]]; then
    info "Uninstalling pwndex..."
    if [[ -f "$INSTALL_PATH" ]]; then
        rm -f "$INSTALL_PATH"
        ok "Removed $INSTALL_PATH"
    else
        warn "$INSTALL_PATH not found — nothing to remove"
    fi
    CACHE_DIR="$(eval echo ~${SUDO_USER:-root}/.cache/pwndex)"
    if [[ -d "$CACHE_DIR" ]]; then
        read -rp "Remove cache directory $CACHE_DIR? [y/N] " ans
        if [[ "${ans,,}" == "y" ]]; then
            rm -rf "$CACHE_DIR"
            ok "Removed cache"
        fi
    fi
    ok "Uninstall complete"
    exit 0
fi

echo -e "\n${BOLD}pwndex installer${RESET}\n"

# ── Check pwndex script exists ────────────────────────────────────────────
if [[ ! -f "$SCRIPT" ]]; then
    die "pwndex script not found at $SCRIPT"
fi

# ── apt dependencies ──────────────────────────────────────────────────────────
info "Updating apt cache..."
apt-get update -qq

APT_PACKAGES=(
    python3
    python3-rich       # markdown rendering in TUI
    git                # cloning repos
)

OPTIONAL_PACKAGES=(
    exploitdb          # provides searchsploit (Kali only)
    ddgr               # DuckDuckGo CLI search
    googler            # Google CLI search (fallback)
)

info "Installing required packages..."
apt-get install -y -qq "${APT_PACKAGES[@]}" \
    && ok "Required packages installed" \
    || die "Failed to install required packages"

info "Installing optional packages (failures are non-fatal)..."
for pkg in "${OPTIONAL_PACKAGES[@]}"; do
    if apt-get install -y -qq "$pkg" 2>/dev/null; then
        ok "  $pkg"
    else
        warn "  $pkg not available — skipping (some features may be limited)"
    fi
done

# ── Install pwndex ────────────────────────────────────────────────────────
info "Installing pwndex to $INSTALL_PATH..."
cp "$SCRIPT" "$INSTALL_PATH"
chmod 755 "$INSTALL_PATH"
ok "Installed to $INSTALL_PATH"

# ── GitHub token hint ─────────────────────────────────────────────────────────
echo ""
warn "GitHub API rate limits apply to unauthenticated requests."
warn "Set a token for higher limits:"
echo -e "    ${CYAN}export GITHUB_TOKEN=ghp_yourtoken${RESET}"
echo -e "    Add to ${CYAN}~/.bashrc${RESET} or ${CYAN}~/.zshrc${RESET} to persist."

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
info "Verifying install..."
if pwndex --help &>/dev/null; then
    ok "pwndex is working"
else
    die "Install verification failed — check the script manually"
fi

echo ""
echo -e "${BOLD}${GREEN}Done.${RESET} Run: ${CYAN}pwndex <service> [version]${RESET}"
echo -e "Examples:"
echo -e "  ${CYAN}pwndex vesta${RESET}"
echo -e "  ${CYAN}pwndex apache 2.4.49 --rce${RESET}"
echo -e "  ${CYAN}pwndex proftpd 1.3.5 --no-github${RESET}"
echo ""
