#!/bin/sh
# fixiac installer script
# Usage: curl -sSL https://raw.githubusercontent.com/abdmath/fixiac/main/scripts/install.sh | sh
#
# Environment variables:
#   FIXIAC_INSTALL_DIR  — where to install (default: /usr/local/bin)
#   FIXIAC_VERSION      — specific version to install (default: latest)

set -e

REPO="abdmath/fixiac"
INSTALL_DIR="${FIXIAC_INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="fixiac"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info() {
    printf "${CYAN}▸${NC} %s\n" "$1"
}

success() {
    printf "${GREEN}✓${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}!${NC} %s\n" "$1"
}

error() {
    printf "${RED}✗${NC} %s\n" "$1" >&2
    exit 1
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)   echo "Linux" ;;
        Darwin*)  echo "Darwin" ;;
        MINGW*|MSYS*|CYGWIN*) echo "Windows" ;;
        *)        error "Unsupported operating system: $(uname -s)" ;;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "x86_64" ;;
        aarch64|arm64)  echo "arm64" ;;
        *)              error "Unsupported architecture: $(uname -m)" ;;
    esac
}

# Get the latest release version from GitHub API
get_latest_version() {
    if command -v curl > /dev/null 2>&1; then
        curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/'
    elif command -v wget > /dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/'
    else
        error "Either curl or wget is required to download fixiac."
    fi
}

# Download a file
download() {
    local url="$1"
    local output="$2"
    if command -v curl > /dev/null 2>&1; then
        curl -sSL -o "$output" "$url"
    elif command -v wget > /dev/null 2>&1; then
        wget -qO "$output" "$url"
    fi
}

main() {
    echo ""
    printf "${CYAN}  ██████╗ ██╗██╗  ██╗██╗ █████╗  ██████╗${NC}\n"
    printf "${CYAN}  ██╔═══╝ ██║╚██╗██╔╝██║██╔══██╗██╔════╝${NC}\n"
    printf "${CYAN}  █████╗  ██║ ╚███╔╝ ██║███████║██║     ${NC}\n"
    printf "${CYAN}  ██╔══╝  ██║ ██╔██╗ ██║██╔══██║██║     ${NC}\n"
    printf "${CYAN}  ██║     ██║██╔╝ ██╗██║██║  ██║╚██████╗${NC}\n"
    printf "${CYAN}  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝${NC}\n"
    echo ""
    info "Installing fixiac — AI-native Terraform security remediation"
    echo ""

    OS=$(detect_os)
    ARCH=$(detect_arch)

    if [ -n "$FIXIAC_VERSION" ]; then
        VERSION="$FIXIAC_VERSION"
        info "Installing version: v${VERSION}"
    else
        info "Fetching latest version..."
        VERSION=$(get_latest_version)
        if [ -z "$VERSION" ]; then
            error "Could not determine the latest version. Set FIXIAC_VERSION manually or check https://github.com/${REPO}/releases"
        fi
        info "Latest version: v${VERSION}"
    fi

    # Build the download URL
    EXT="tar.gz"
    if [ "$OS" = "Windows" ]; then
        EXT="zip"
    fi

    ARCHIVE="fixiac_${VERSION}_${OS}_${ARCH}.${EXT}"
    URL="https://github.com/${REPO}/releases/download/v${VERSION}/${ARCHIVE}"

    info "Downloading ${ARCHIVE}..."
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    download "$URL" "${TMPDIR}/${ARCHIVE}"

    if [ ! -f "${TMPDIR}/${ARCHIVE}" ]; then
        error "Download failed. Check the URL: ${URL}"
    fi

    # Verify checksum
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/v${VERSION}/checksums.txt"
    download "$CHECKSUM_URL" "${TMPDIR}/checksums.txt" 2>/dev/null || true

    if [ -f "${TMPDIR}/checksums.txt" ]; then
        info "Verifying checksum..."
        cd "$TMPDIR"
        if command -v sha256sum > /dev/null 2>&1; then
            grep "$ARCHIVE" checksums.txt | sha256sum -c --quiet 2>/dev/null && success "Checksum verified" || warn "Checksum verification failed — proceeding anyway"
        elif command -v shasum > /dev/null 2>&1; then
            grep "$ARCHIVE" checksums.txt | shasum -a 256 -c --quiet 2>/dev/null && success "Checksum verified" || warn "Checksum verification failed — proceeding anyway"
        fi
        cd - > /dev/null
    fi

    # Extract
    info "Extracting..."
    if [ "$EXT" = "tar.gz" ]; then
        tar xzf "${TMPDIR}/${ARCHIVE}" -C "$TMPDIR"
    else
        unzip -q "${TMPDIR}/${ARCHIVE}" -d "$TMPDIR"
    fi

    # Install
    if [ ! -d "$INSTALL_DIR" ]; then
        mkdir -p "$INSTALL_DIR"
    fi

    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMPDIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        info "Elevated permissions required to install to ${INSTALL_DIR}"
        sudo mv "${TMPDIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

    echo ""
    success "fixiac v${VERSION} installed to ${INSTALL_DIR}/${BINARY_NAME}"
    echo ""
    info "Get started:"
    echo "    fixiac --help"
    echo "    fixiac scan ./terraform"
    echo ""
    info "Configure an LLM provider:"
    echo "    export FIXIAC_LLM_API_KEY=\"your-api-key\""
    echo "    fixiac config set llm.provider groq"
    echo ""
}

main "$@"
