#!/usr/bin/env bash
#============================================================
# CDN-Unmasker – Installer
# Detects your OS, installs missing dependencies, downloads
# the SecLists wordlist, and clones CloudRip.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#============================================================

set -euo pipefail

# --- Colors ------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[*]${NC} $*"; }
ok()      { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
fail()    { echo -e "${RED}[-]${NC} $*"; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}$*${NC}"; }
sep()     { echo -e "${CYAN}──────────────────────────────────────────${NC}"; }

# --- Config ------------------------------------------------
WORDLIST_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt"
WORDLIST_FILE="subdomains-top1million-110000.txt"
CLOUDRIP_REPO="https://github.com/staxsum/CloudRip.git"
CLOUDRIP_DIR="CloudRip"

# --- Helpers -----------------------------------------------
has() { command -v "$1" >/dev/null 2>&1; }

# --- Detect OS ---------------------------------------------
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [ -f /etc/os-release ]; then
        local id
        id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
        case "$id" in
            ubuntu|debian|kali|parrot)  echo "debian" ;;
            fedora|rhel|centos|rocky)   echo "fedora" ;;
            arch|manjaro|blackarch)     echo "arch"   ;;
            *)                          echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

# ===========================================================
#  BANNER
# ===========================================================
clear
echo -e "${BOLD}${CYAN}"
cat <<'BANNER'
   ___  ___  _  _       _   _
  / __||   \| \| | ___ | | | |_ __  _ __  __ _ ___| | _____ _ _
 | (__ | |) | .` ||___|| |_| | '  \| '  \/ _` (_-<| |/ / -_) '_|
  \___||___/|_|\_|      \___/|_|_|_|_|_|_\__,_/__/|___/\___|_|

  Installer v3.4
BANNER
echo -e "${NC}"
sep

# ===========================================================
#  DETECT OS
# ===========================================================
header "Detecting system..."
OS=$(detect_os)

case "$OS" in
    debian)  ok "Detected: Debian / Ubuntu / Kali / Parrot" ;;
    fedora)  ok "Detected: Fedora / RHEL / CentOS" ;;
    arch)    ok "Detected: Arch / Manjaro / BlackArch" ;;
    macos)   ok "Detected: macOS" ;;
    unknown) warn "Unknown OS — some packages may need manual installation." ;;
esac

# ===========================================================
#  SYSTEM PACKAGES
# ===========================================================
header "Checking system packages..."

# Each entry is "binary:package_name" — binary is what we check,
# package_name is what the package manager installs.
install_system_packages() {
    local missing_pkgs=()

    for entry in "$@"; do
        local bin="${entry%%:*}"
        local pkg="${entry##*:}"
        if has "$bin"; then
            ok "$bin — already installed"
        else
            warn "$bin — missing, will install ($pkg)"
            missing_pkgs+=("$pkg")
        fi
    done

    if [ ${#missing_pkgs[@]} -eq 0 ]; then
        return 0
    fi

    info "Installing: ${missing_pkgs[*]}"
    case "$OS" in
        debian) sudo apt-get update -qq && sudo apt-get install -y "${missing_pkgs[@]}" ;;
        fedora) sudo dnf install -y "${missing_pkgs[@]}" ;;
        arch)   sudo pacman -Sy --noconfirm "${missing_pkgs[@]}" ;;
        macos)
            if ! has brew; then
                warn "Homebrew not found — installing..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install "${missing_pkgs[@]}"
            ;;
        *)
            warn "Cannot auto-install on this OS. Install manually: ${missing_pkgs[*]}"
            ;;
    esac
}

case "$OS" in
    debian)
        install_system_packages \
            "jq:jq" "whois:whois" "dig:dnsutils" \
            "openssl:openssl" "grepcidr:grepcidr" \
            "curl:curl" "python3:python3" "nmap:nmap" "git:git"
        ;;
    fedora)
        install_system_packages \
            "jq:jq" "whois:whois" "dig:bind-utils" \
            "openssl:openssl" "grepcidr:grepcidr" \
            "curl:curl" "python3:python3" "nmap:nmap" "git:git"
        ;;
    arch)
        install_system_packages \
            "jq:jq" "whois:whois" "dig:bind" \
            "openssl:openssl" "grepcidr:grepcidr" \
            "curl:curl" "python3:python3" "nmap:nmap" "git:git"
        ;;
    macos)
        install_system_packages \
            "jq:jq" "whois:whois" "dig:bind" \
            "openssl:openssl" "grepcidr:grepcidr" \
            "curl:curl" "python3:python3" "nmap:nmap" "git:git"
        ;;
    *)
        warn "Skipping auto-install. Check manually: jq whois dig openssl grepcidr curl python3 nmap git"
        ;;
esac

# ===========================================================
#  GO TOOLS
# ===========================================================
header "Checking Go tools..."

install_go_tool() {
    local bin="$1"
    local pkg="$2"
    if has "$bin"; then
        ok "$bin — already installed"
    else
        info "Installing $bin..."
        if go install "$pkg" 2>/dev/null; then
            ok "$bin installed."
        else
            warn "Failed to install $bin. Try manually:"
            warn "  go install $pkg"
        fi
    fi
}

if ! has go; then
    warn "Go is not installed. Go tools will be skipped."
    echo ""
    case "$OS" in
        debian) echo -e "  Install Go:  ${YELLOW}sudo apt install golang-go${NC}" ;;
        fedora) echo -e "  Install Go:  ${YELLOW}sudo dnf install golang${NC}" ;;
        arch)   echo -e "  Install Go:  ${YELLOW}sudo pacman -S go${NC}" ;;
        macos)  echo -e "  Install Go:  ${YELLOW}brew install go${NC}" ;;
        *)      echo -e "  Download Go: ${YELLOW}https://go.dev/dl/${NC}" ;;
    esac
    echo -e "  Then re-run this installer."
    echo ""
    warn "Missing Go tools: subfinder assetfinder httpx ffuf gobuster"
else
    ok "Go — $(go version | awk '{print $3}')"

    # Ensure GOPATH/bin is in PATH
    GOBIN="${GOPATH:-$HOME/go}/bin"
    if [[ ":$PATH:" != *":$GOBIN:"* ]]; then
        warn "GOPATH bin not in PATH. Add to your shell profile:"
        echo -e "  ${YELLOW}export PATH=\$PATH:$GOBIN${NC}"
    fi

    install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"
    install_go_tool "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool "ffuf"        "github.com/ffuf/ffuf/v2@latest"
    install_go_tool "gobuster"    "github.com/OJ/gobuster/v3@latest"
fi

# ===========================================================
#  WORDLIST
# ===========================================================
header "Checking wordlist..."

if [ -f "$WORDLIST_FILE" ]; then
    lines=$(wc -l < "$WORDLIST_FILE")
    ok "Wordlist already present ($lines lines): $WORDLIST_FILE"
else
    info "Downloading SecLists subdomain wordlist (110k entries)..."
    if curl -fsSL --progress-bar "$WORDLIST_URL" -o "$WORDLIST_FILE"; then
        ok "Wordlist saved: $WORDLIST_FILE"
    else
        warn "Download failed. Try manually:"
        warn "  curl -L $WORDLIST_URL -o $WORDLIST_FILE"
        warn "  wget $WORDLIST_URL"
    fi
fi

# ===========================================================
#  CLOUDRIP
# ===========================================================
header "Checking CloudRip..."

if [ -f "./cloudrip.py" ]; then
    ok "cloudrip.py already present."
elif [ -d "$CLOUDRIP_DIR" ] && [ -f "$CLOUDRIP_DIR/cloudrip.py" ]; then
    info "Found CloudRip directory — copying cloudrip.py..."
    cp "$CLOUDRIP_DIR/cloudrip.py" ./cloudrip.py
    ok "cloudrip.py copied."
else
    info "Cloning CloudRip from GitHub..."
    if git clone --depth 1 "$CLOUDRIP_REPO" "$CLOUDRIP_DIR" 2>/dev/null; then
        cp "$CLOUDRIP_DIR/cloudrip.py" ./cloudrip.py
        ok "cloudrip.py ready."
    else
        warn "Clone failed. Install manually:"
        warn "  git clone $CLOUDRIP_REPO"
        warn "  cp CloudRip/cloudrip.py ."
    fi
fi

# ===========================================================
#  PERMISSIONS
# ===========================================================
header "Setting permissions..."

if [ -f "./cdn_unmasker.sh" ]; then
    chmod +x ./cdn_unmasker.sh
    ok "cdn_unmasker.sh is executable."
else
    warn "cdn_unmasker.sh not found in the current directory."
fi

# ===========================================================
#  FINAL VERIFICATION
# ===========================================================
header "Final dependency check..."
sep

REQUIRED=(
    "subfinder" "assetfinder" "httpx" "ffuf" "gobuster"
    "jq" "whois" "dig" "openssl" "python3" "grepcidr" "curl"
)
ALL_OK=true

for tool in "${REQUIRED[@]}"; do
    if has "$tool"; then
        echo -e "  ${GREEN}✔${NC}  $tool"
    else
        echo -e "  ${RED}✘${NC}  $tool  ${RED}← missing${NC}"
        ALL_OK=false
    fi
done

if [ -f "./cloudrip.py" ]; then
    echo -e "  ${GREEN}✔${NC}  cloudrip.py"
else
    echo -e "  ${RED}✘${NC}  cloudrip.py  ${RED}← missing${NC}"
    ALL_OK=false
fi

if [ -f "$WORDLIST_FILE" ]; then
    echo -e "  ${GREEN}✔${NC}  $WORDLIST_FILE"
else
    echo -e "  ${RED}✘${NC}  $WORDLIST_FILE  ${RED}← missing${NC}"
    ALL_OK=false
fi

sep

if $ALL_OK; then
    echo -e "\n${GREEN}${BOLD}  All dependencies satisfied. You are ready.${NC}\n"
    echo -e "  ${BOLD}Basic scan:${NC}"
    echo -e "    ./cdn_unmasker.sh example.com\n"
    echo -e "  ${BOLD}Full scan with report and nmap:${NC}"
    echo -e "    ./cdn_unmasker.sh example.com --report --nmap\n"
else
    echo -e "\n${YELLOW}${BOLD}  Some dependencies are still missing (see ✘ above).${NC}"
    echo -e "  Resolve them, then run the script:\n"
    echo -e "    ${BOLD}./cdn_unmasker.sh example.com${NC}\n"
fi
