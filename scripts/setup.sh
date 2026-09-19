#!/usr/bin/env bash
set -euo pipefail

# Sidecar Setup Script
# Installs sidecar and optionally td for AI-assisted development workflows

VERSION="1.2.0"

# Colors (used in plain mode)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Flags
YES_FLAG=false
FORCE_FLAG=false
SIDECAR_ONLY=false
HELP_FLAG=false
USE_GUM=false
BUILD_FROM_SOURCE=false
ALLOW_LEGACY_BINARY=false
SIDECAR_VERSION_PIN=""

# Versions (populated during detection)
GO_VERSION=""
TD_VERSION=""
SIDECAR_VERSION=""
LATEST_TD=""
LATEST_SIDECAR=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -y|--yes)
            YES_FLAG=true
            shift
            ;;
        -f|--force)
            FORCE_FLAG=true
            shift
            ;;
        --sidecar-only)
            SIDECAR_ONLY=true
            shift
            ;;
        --build-from-source)
            # Explicit opt-in: skip precompiled assets and build with the local
            # Go toolchain. Never implied by a failed binary verification.
            BUILD_FROM_SOURCE=true
            shift
            ;;
        --allow-legacy-binary)
            # Emergency escape hatch for releases published before provenance
            # existed. Installs with TLS-only integrity (like the old script);
            # off by default and logged loudly.
            ALLOW_LEGACY_BINARY=true
            shift
            ;;
        --version)
            [[ $# -ge 2 ]] || { echo "--version requires vX.Y.Z" >&2; exit 2; }
            SIDECAR_VERSION_PIN="$2"
            shift 2
            ;;
        -h|--help)
            HELP_FLAG=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [[ -n "$SIDECAR_VERSION_PIN" ]] && \
  ! [[ "$SIDECAR_VERSION_PIN" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "--version must be strict SemVer vX.Y.Z: $SIDECAR_VERSION_PIN" >&2
  exit 2
fi

show_help() {
  cat << EOF
Sidecar Setup Script v${VERSION}

Usage: setup.sh [OPTIONS]

Precompiled sidecar binaries are installed only after full supply-chain
verification: the release checksums are signed by a Sigstore certificate bound
to the sidecar release workflow, each archive carries an SLSA provenance
attestation pinning the exact tag commit, and a signed SBOM ties the archive
digest and main-module version to that commit. Verification runs fully offline
from the signature bundles published with the release. Releases without
provenance are treated as legacy and are not installed from precompiled assets
by default.

Options:
  -y, --yes              Skip all prompts (for CI/headless installs)
  -f, --force            Reinstall even if versions are up-to-date
  --sidecar-only         Install only sidecar, skip td
  --build-from-source    Skip precompiled assets; build with local Go (explicit)
  --allow-legacy-binary  Allow a legacy (unsigned) release, TLS-only (explicit)
  --version vX.Y.Z       Pin a specific sidecar release tag
  -h, --help             Show this help message

Examples:
  # Interactive install
  curl -fsSL https://raw.githubusercontent.com/marcus/sidecar/main/scripts/setup.sh | bash

  # Headless install (both tools)
  curl -fsSL https://raw.githubusercontent.com/marcus/sidecar/main/scripts/setup.sh | bash -s -- --yes

  # Headless install (sidecar only)
  curl -fsSL https://raw.githubusercontent.com/marcus/sidecar/main/scripts/setup.sh | bash -s -- --yes --sidecar-only
EOF
}

if $HELP_FLAG; then
    show_help
    exit 0
fi

# Platform detection
detect_platform() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        Linux)
            if grep -qi microsoft /proc/version 2>/dev/null; then
                echo "wsl"
            else
                echo "linux"
            fi
            ;;
        *) echo "unsupported" ;;
    esac
}

PLATFORM=$(detect_platform)

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) echo "unsupported" ;;
    esac
}

ARCH=$(detect_arch)

detect_os() {
    case "$(uname -s)" in
        Darwin) echo "darwin" ;;
        Linux) echo "linux" ;;
        *) echo "" ;;
    esac
}

if [[ "$PLATFORM" == "unsupported" ]]; then
    echo -e "${RED}Unsupported platform. This script supports macOS, Linux, and WSL.${NC}"
    exit 1
fi

if [[ "$PLATFORM" == "wsl" ]]; then
    echo -e "${YELLOW}WSL detected. WSL support is experimental.${NC}"
fi

# Gum helpers with plain fallback
try_install_gum() {
    if command -v gum &> /dev/null; then
        USE_GUM=true
        return 0
    fi

    # Try to install gum (terminal UI toolkit for nicer prompts/spinners)
    local install_cmd=""
    local install_name="gum"

    if command -v brew &> /dev/null; then
        install_cmd="brew install gum"
    elif command -v nix-env &> /dev/null; then
        install_cmd="nix-env -iA nixpkgs.gum"
    elif command -v apt &> /dev/null; then
        # gum requires adding the charm repo on Debian/Ubuntu
        install_cmd=""  # Skip - too complex for auto-install
    elif command -v dnf &> /dev/null; then
        install_cmd="dnf install -y gum"
    elif command -v pacman &> /dev/null; then
        install_cmd="pacman -S --noconfirm gum"
    fi

    if [[ -n "$install_cmd" ]]; then
        echo ""
        echo "Installing gum (terminal UI toolkit for better prompts)..."
        echo "  This may take a minute..."
        echo ""
        if $install_cmd 2>&1 | head -20; then
            if command -v gum &> /dev/null; then
                USE_GUM=true
                echo "Done."
                return 0
            fi
        fi
    fi

    # Fall back to plain mode
    USE_GUM=false
    return 0
}

# UI helpers that work in both gum and plain mode
style_header() {
    if $USE_GUM; then
        gum style --foreground 212 --bold "$1"
    else
        echo -e "${BOLD}${BLUE}$1${NC}"
    fi
}

style_success() {
    if $USE_GUM; then
        gum style --foreground 2 "$1"
    else
        echo -e "${GREEN}$1${NC}"
    fi
}

style_warning() {
    if $USE_GUM; then
        gum style --foreground 3 "$1"
    else
        echo -e "${YELLOW}$1${NC}"
    fi
}

style_error() {
    if $USE_GUM; then
        gum style --foreground 1 "$1"
    else
        echo -e "${RED}$1${NC}"
    fi
}

confirm() {
    local prompt="$1"
    local default="${2:-y}"

    if $YES_FLAG; then
        return 0
    fi

    if $USE_GUM; then
        gum confirm "$prompt"
        return $?
    else
        local yn
        if [[ "$default" == "y" ]]; then
            read -p "$prompt [Y/n] " yn
            yn=${yn:-y}
        else
            read -p "$prompt [y/N] " yn
            yn=${yn:-n}
        fi
        [[ "$yn" =~ ^[Yy] ]]
    fi
}

# Explicit, default-NO choice. Unlike confirm(), --yes never auto-accepts:
# falling back to a source build after a failed verification must always be a
# deliberate decision by a human.
choose_source_build() {
    local prompt="$1" yn
    if $YES_FLAG; then
        return 1
    fi
    read -r -p "$prompt [y/N] " yn || true
    [[ "$yn" =~ ^[Yy] ]]
}

choose() {
    local prompt="$1"
    shift
    local options=("$@")

    if $YES_FLAG; then
        echo "${options[0]}"
        return 0
    fi

    if $USE_GUM; then
        gum choose --header "$prompt" "${options[@]}"
    else
        echo "$prompt"
        local i=1
        for opt in "${options[@]}"; do
            echo "  $i) $opt"
            ((i++))
        done
        local choice
        read -p "Select [1-${#options[@]}]: " choice
        choice=${choice:-1}
        echo "${options[$((choice-1))]}"
    fi
}

spin() {
    local title="$1"
    shift
    local ret

    if $USE_GUM; then
        gum spin --spinner dot --title "$title" -- "$@"
        ret=$?
    else
        echo "$title"
        "$@"
        ret=$?
    fi

    if [[ $ret -ne 0 ]]; then
        style_error "Command failed (exit code $ret)"
    fi
    return $ret
}

# Version helpers
get_go_version() {
    if command -v go &> /dev/null; then
        go version | grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | sed 's/go//'
    else
        echo ""
    fi
}

get_td_version() {
    local td_bin=""
    # Check PATH first, then check go bin directory directly
    if command -v td &> /dev/null; then
        td_bin="td"
    elif command -v go &> /dev/null; then
        local go_bin
        go_bin=$(get_go_bin)
        if [[ -x "$go_bin/td" ]]; then
            td_bin="$go_bin/td"
        fi
    fi

    if [[ -n "$td_bin" ]]; then
        local v
        v=$("$td_bin" version --short 2>/dev/null || true)
        if [[ -z "$v" ]]; then
            v=$("$td_bin" version 2>/dev/null | head -1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || true)
        fi
        echo "$v"
    else
        echo ""
    fi
}

get_sidecar_version() {
    local sidecar_bin=""
    # Check PATH first, then check go bin directory directly
    if command -v sidecar &> /dev/null; then
        sidecar_bin="sidecar"
    elif command -v go &> /dev/null; then
        local go_bin
        go_bin=$(get_go_bin)
        if [[ -x "$go_bin/sidecar" ]]; then
            sidecar_bin="$go_bin/sidecar"
        fi
    fi

    if [[ -n "$sidecar_bin" ]]; then
        "$sidecar_bin" --version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo ""
    else
        echo ""
    fi
}

get_tmux_version() {
    if command -v tmux &> /dev/null; then
        tmux -V | grep -oE '[0-9]+\.[0-9]+[a-z]*' | head -1
    else
        echo ""
    fi
}

get_latest_release() {
    local repo="$1"
    local url="https://api.github.com/repos/${repo}/releases/latest"
    curl -fsSL "$url" 2>/dev/null | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
}

version_gte() {
    local v1="$1"
    local v2="$2"
    # Remove 'v' prefix
    v1="${v1#v}"
    v2="${v2#v}"

    printf '%s\n%s\n' "$v2" "$v1" | sort -V | head -n1 | grep -q "^${v2}$"
}

# Check if PATH includes go/bin
check_go_path() {
    local go_bin
    go_bin=$(get_go_bin)
    echo "$PATH" | tr ':' '\n' | grep -qF "$go_bin"
}

get_shell_rc() {
    local shell_name
    shell_name=$(basename "$SHELL")
    case "$shell_name" in
        zsh) echo "$HOME/.zshrc" ;;
        bash)
            if [[ -f "$HOME/.bashrc" ]]; then
                echo "$HOME/.bashrc"
            else
                echo "$HOME/.bash_profile"
            fi
            ;;
        fish)
            local fish_config="$HOME/.config/fish/config.fish"
            mkdir -p "$(dirname "$fish_config")"
            echo "$fish_config"
            ;;
        *) echo "$HOME/.profile" ;;
    esac
}

is_fish_shell() {
    [[ "$(basename "$SHELL")" == "fish" ]]
}

get_go_bin() {
    local gobin
    gobin=$(go env GOBIN 2>/dev/null)
    if [[ -n "$gobin" ]]; then
        echo "$gobin"
    else
        local gopath
        gopath=$(go env GOPATH 2>/dev/null)
        echo "${gopath:-$HOME/go}/bin"
    fi
}

# ---------------------------------------------------------------------------
# Verified precompiled-binary installation
#
# TLS alone only proves bytes came from GitHub; it cannot prove the expected
# release workflow produced them. Every precompiled install therefore checks,
# BEFORE the archive is extracted or copied:
#   1. checksums.txt is signed by a Fulcio certificate whose OIDC claims pin
#      it to the release workflow of the expected repository, running on the
#      expected tag, triggered by a tag push; the archive digest matches.
#   2. an SLSA v1 provenance attestation covers the archive itself (subject
#      digest) and pins repository, tag and source commit.
#   3. a CycloneDX SBOM signed by the same identity describes the archive
#      (main component github.com/marcus/sidecar at the tag, archive digest,
#      VCS reference pinned to the same commit as the provenance).
# The .bundle files carry the certificate chain and Rekor inclusion proof, so
# with the embedded Sigstore trusted root all checks run fully OFFLINE.
#
# install_verified_sidecar result codes:
#   0  verified and installed   (stdout: source commit)
#  10  legacy release (no provenance published)
#  11  verification failed (tamper / wrong identity / incomplete materials)
#  12  required materials could not be fetched (network)
#  13  platform/architecture unsupported
#  14  verifier (cosign) unavailable and could not be bootstrapped
# ---------------------------------------------------------------------------

SIDECAR_REPO="${SIDECAR_REPO_OVERRIDE:-marcus/sidecar}"
SIDECAR_RELEASE_BASE_URL_DEFAULT="https://github.com/${SIDECAR_REPO}/releases/download"

# Cosign is the verifier. When not present it is bootstrapped from the official
# Sigstore release and matched against these pinned SHA-256 digests
# (cosign v3.1.3; cross-checked against the upstream cosign_checksums.txt and
# by hashing a downloaded binary independently). Bump all four together, after
# verifying the upstream checksum file out of band.
COSIGN_BOOTSTRAP_VERSION="v3.1.3"
cosign_pinned_sha() {
    case "$1/$2" in
        darwin/amd64) echo "2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c" ;;
        darwin/arm64) echo "5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76" ;;
        linux/amd64)  echo "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71" ;;
        linux/arm64)  echo "c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a" ;;
        *) return 1 ;;
    esac
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# http_download URL OUTFILE -> prints ok | notfound | error. curl follows
# redirects (release URLs redirect to object storage); a 404 is a distinct
# answer so legacy releases are not confused with an unreachable network.
http_download() {
    local url="$1" out="$2" code
    code=$(curl -sSL --retry 2 --connect-timeout 10 \
        -o "$out" -w '%{http_code}' "$url" 2>/dev/null) || {
        rm -f "$out"
        echo "error"
        return 0
    }
    case "$code" in
        2*)
            if [[ -s "$out" ]]; then echo "ok"; else rm -f "$out"; echo "error"; fi
            ;;
        404)
            rm -f "$out"
            echo "notfound"
            ;;
        *)
            rm -f "$out"
            echo "error"
            ;;
    esac
}

resolve_install_dir() {
    if [[ -d "/usr/local/bin" && -w "/usr/local/bin" ]]; then
        echo "/usr/local/bin"
    elif command -v go >/dev/null 2>&1; then
        get_go_bin
    else
        echo "$HOME/.local/bin"
    fi
}

# Cosign verifier: reuse an installed cosign, otherwise bootstrap a pinned one
# into the scratch directory. A wrong digest is removed and refused.
ensure_cosign() {
    local work="$1"
    if [[ -n "${SIDECAR_COSIGN_BIN:-}" ]]; then
        if [[ -x "$SIDECAR_COSIGN_BIN" ]] && "$SIDECAR_COSIGN_BIN" version >/dev/null 2>&1; then
            echo "$SIDECAR_COSIGN_BIN"
            return 0
        fi
        return 14
    fi
    if command -v cosign >/dev/null 2>&1 && cosign version >/dev/null 2>&1; then
        echo "cosign"
        return 0
    fi

    local os arch asset expected url out actual st
    os=$(detect_os)
    arch=$(detect_arch)
    [[ -n "$os" && "$arch" != "unsupported" ]] || return 14
    asset="cosign-$os-$arch"
    expected=$(cosign_pinned_sha "$os" "$arch") || return 14
    # SIDECAR_COSIGN_BOOTSTRAP_BASE_URL is a test seam for the pinned-hash
    # check; production always uses the official Sigstore release URL.
    url="${SIDECAR_COSIGN_BOOTSTRAP_BASE_URL:-https://github.com/sigstore/cosign/releases/download}/${COSIGN_BOOTSTRAP_VERSION}/${asset}"
    out="$work/cosign"
    st=$(http_download "$url" "$out")
    [[ "$st" == "ok" ]] || return 14
    actual=$(sha256_file "$out")
    if [[ "$actual" != "$expected" ]]; then
        echo "bootstrapped cosign digest mismatch: expected $expected, got $actual" >&2
        rm -f "$out"
        return 14
    fi
    chmod 0755 "$out" || return 14
    "$out" version >/dev/null 2>&1 || return 14
    echo "$out"
}

# Public-good Sigstore trust root, vendored at packaging/sigstore/trusted_root.json
# and embedded here so this script stays a single curl|bash file. It pins the
# Fulcio roots, Rekor log key and timestamp authority used for OFFLINE bundle
# verification; refresh it by re-running `cosign initialize` and regenerating
# this block.
write_trusted_root() {
    local out="$1"
    base64 --decode >"$out" <<'SIDECAR_TRUSTED_ROOT_EOF'
ewogICJtZWRpYVR5cGUiOiAiYXBwbGljYXRpb24vdm5kLmRldi5zaWdzdG9yZS50cnVzdGVkcm9v
dCtqc29uO3ZlcnNpb249MC4xIiwKICAidGxvZ3MiOiBbCiAgICB7CiAgICAgICJiYXNlVXJsIjog
Imh0dHBzOi8vcmVrb3Iuc2lnc3RvcmUuZGV2IiwKICAgICAgImhhc2hBbGdvcml0aG0iOiAiU0hB
Ml8yNTYiLAogICAgICAicHVibGljS2V5IjogewogICAgICAgICJyYXdCeXRlcyI6ICJNRmt3RXdZ
SEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUUyRzJZKzJ0YWJkVFY1QmNHaUJJeDBhOWZBRndy
a0JibUxTR3RrczRMM3FYNnlZWTB6dWZCbmhDOFVyL2l5NTVHaFdQLzlBL2JZMkxoQzMwTTkrUll0
dz09IiwKICAgICAgICAia2V5RGV0YWlscyI6ICJQS0lYX0VDRFNBX1AyNTZfU0hBXzI1NiIsCiAg
ICAgICAgInZhbGlkRm9yIjogewogICAgICAgICAgInN0YXJ0IjogIjIwMjEtMDEtMTJUMTE6NTM6
MjdaIgogICAgICAgIH0KICAgICAgfSwKICAgICAgImxvZ0lkIjogewogICAgICAgICJrZXlJZCI6
ICJ3Tkk5YXRRR2x6K1ZXZk82TFJ5Z0g0UVVmWS84VzRSRndpVDVpNVdSZ0IwPSIKICAgICAgfQog
ICAgfSwKICAgIHsKICAgICAgImJhc2VVcmwiOiAiaHR0cHM6Ly9sb2cyMDI1LTEucmVrb3Iuc2ln
c3RvcmUuZGV2IiwKICAgICAgImhhc2hBbGdvcml0aG0iOiAiU0hBMl8yNTYiLAogICAgICAicHVi
bGljS2V5IjogewogICAgICAgICJyYXdCeXRlcyI6ICJNQ293QlFZREsyVndBeUVBdDhybHAxa25H
d2pmYmNYQVlQWUFrbjBYaUx6MXg4TzR0MFlrRWhpZTI0ND0iLAogICAgICAgICJrZXlEZXRhaWxz
IjogIlBLSVhfRUQyNTUxOSIsCiAgICAgICAgInZhbGlkRm9yIjogewogICAgICAgICAgInN0YXJ0
IjogIjIwMjUtMDktMjNUMDA6MDA6MDBaIgogICAgICAgIH0KICAgICAgfSwKICAgICAgImxvZ0lk
IjogewogICAgICAgICJrZXlJZCI6ICJ6eEdaRlZ2ZDBGRW1qUjhXckZ3TWRjQUo5dnRhWS9RWGY0
NFkxd1VlUDZBPSIKICAgICAgfQogICAgfQogIF0sCiAgImNlcnRpZmljYXRlQXV0aG9yaXRpZXMi
OiBbCiAgICB7CiAgICAgICJzdWJqZWN0IjogewogICAgICAgICJvcmdhbml6YXRpb24iOiAic2ln
c3RvcmUuZGV2IiwKICAgICAgICAiY29tbW9uTmFtZSI6ICJzaWdzdG9yZSIKICAgICAgfSwKICAg
ICAgInVyaSI6ICJodHRwczovL2Z1bGNpby5zaWdzdG9yZS5kZXYiLAogICAgICAiY2VydENoYWlu
IjogewogICAgICAgICJjZXJ0aWZpY2F0ZXMiOiBbCiAgICAgICAgICB7CiAgICAgICAgICAgICJy
YXdCeXRlcyI6ICJNSUlCK0RDQ0FYNmdBd0lCQWdJVE5Wa0Rab0Npb2ZQRHN5N2RmbTZnZUxidWh6
QUtCZ2dxaGtqT1BRUURBekFxTVJVd0V3WURWUVFLRXd4emFXZHpkRzl5WlM1a1pYWXhFVEFQQmdO
VkJBTVRDSE5wWjNOMGIzSmxNQjRYRFRJeE1ETXdOekF6TWpBeU9Wb1hEVE14TURJeU16QXpNakF5
T1Zvd0tqRVZNQk1HQTFVRUNoTU1jMmxuYzNSdmNtVXVaR1YyTVJFd0R3WURWUVFERXdoemFXZHpk
Rzl5WlRCMk1CQUdCeXFHU000OUFnRUdCU3VCQkFBaUEySUFCTFN5QTdJaTVrK3BOTzhaRVdZMHls
ZW1XRG93T2tOYTNrTCtHWkU1WjVHV2VoTDkvQTliUk5BM1JicnNaNWkwSmNhc3RhUkw3U3A1ZnAv
akQ1ZHhxYy9VZFRWbmx2UzE2YW4rMllmc3dlL1F1TG9sUlVDcmNPRTIrMmlBNSt0emQ2Tm1NR1F3
RGdZRFZSMFBBUUgvQkFRREFnRUdNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUV3SFFZRFZSME9C
QllFRk1qRkhRQkJtaVFwTWxFazZ3MnVTdTFLQnRQc01COEdBMVVkSXdRWU1CYUFGTWpGSFFCQm1p
UXBNbEVrNncydVN1MUtCdFBzTUFvR0NDcUdTTTQ5QkFNREEyZ0FNR1VDTUg4bGlXSmZNdWk2dlhY
QmhqRGdZNE13c2xtTi9USnhWZS84M1dyRm9td21OZjA1NnkxWDQ4RjljNG0zYTNvelhBSXhBS2pS
YXk1L2FqL2pzS0tHSWttUWF0akk4dXVwSHIvK0N4RnZhSldtcFlxTmtMREdSVSs5b3J6aDVoSTJS
cmN1YVE9PSIKICAgICAgICAgIH0KICAgICAgICBdCiAgICAgIH0sCiAgICAgICJ2YWxpZEZvciI6
IHsKICAgICAgICAic3RhcnQiOiAiMjAyMS0wMy0wN1QwMzoyMDoyOVoiLAogICAgICAgICJlbmQi
OiAiMjAyMi0xMi0zMVQyMzo1OTo1OS45OTlaIgogICAgICB9CiAgICB9LAogICAgewogICAgICAi
c3ViamVjdCI6IHsKICAgICAgICAib3JnYW5pemF0aW9uIjogInNpZ3N0b3JlLmRldiIsCiAgICAg
ICAgImNvbW1vbk5hbWUiOiAic2lnc3RvcmUiCiAgICAgIH0sCiAgICAgICJ1cmkiOiAiaHR0cHM6
Ly9mdWxjaW8uc2lnc3RvcmUuZGV2IiwKICAgICAgImNlcnRDaGFpbiI6IHsKICAgICAgICAiY2Vy
dGlmaWNhdGVzIjogWwogICAgICAgICAgewogICAgICAgICAgICAicmF3Qnl0ZXMiOiAiTUlJQ0dq
Q0NBYUdnQXdJQkFnSVVBTG5WaVZmblUwYnJKYXNtUmtIcm4vVW5mYVF3Q2dZSUtvWkl6ajBFQXdN
d0tqRVZNQk1HQTFVRUNoTU1jMmxuYzNSdmNtVXVaR1YyTVJFd0R3WURWUVFERXdoemFXZHpkRzl5
WlRBZUZ3MHlNakEwTVRNeU1EQTJNVFZhRncwek1URXdNRFV4TXpVMk5UaGFNRGN4RlRBVEJnTlZC
QW9UREhOcFozTjBiM0psTG1SbGRqRWVNQndHQTFVRUF4TVZjMmxuYzNSdmNtVXRhVzUwWlhKdFpX
UnBZWFJsTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUU4UlZTL3lzSCtOT3Z1RFp5UEla
dGlsZ1VGOU5sYXJZcEFkOUhQMXZCQkgxVTVDVjc3TFNTN3MwWmlING5FN0h2N3B0UzZMdnZSL1NU
azc5OExWZ016TGxKNEhlSWZGM3RIU2FleExjWXBTQVNyMWtTME4vUmdCSnovOWpXQ2lYbm8zc3dl
VEFPQmdOVkhROEJBZjhFQkFNQ0FRWXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUhBd013RWdZRFZS
MFRBUUgvQkFnd0JnRUIvd0lCQURBZEJnTlZIUTRFRmdRVTM5UHB6MVlrRVpiNXFOanBLRldpeGk0
WVpEOHdId1lEVlIwakJCZ3dGb0FVV01BZVg1RkZwV2FwZXN5UW9aTWkwQ3JGeGZvd0NnWUlLb1pJ
emowRUF3TURad0F3WkFJd1BDc1FLNERZaVpZRFBJYURpNUhGS25meFh4NkFTU1ZtRVJmc3luWUJp
WDJYNlNKUm5aVTg0LzlEWmRuRnZ2eG1BakJPdDZRcEJsYzRKLzBEeHZrVENxcGNsdnppTDZCQ0NQ
bmpkbElCM1B1M0J4c1BteWdVWTdJaTJ6YmRDZGxpaW93PSIKICAgICAgICAgIH0sCiAgICAgICAg
ICB7CiAgICAgICAgICAgICJyYXdCeXRlcyI6ICJNSUlCOXpDQ0FYeWdBd0lCQWdJVUFMWk5BUEZk
eEhQd2plRGxvRHd5WUNoQU8vNHdDZ1lJS29aSXpqMEVBd013S2pFVk1CTUdBMVVFQ2hNTWMybG5j
M1J2Y21VdVpHVjJNUkV3RHdZRFZRUURFd2h6YVdkemRHOXlaVEFlRncweU1URXdNRGN4TXpVMk5U
bGFGdzB6TVRFd01EVXhNelUyTlRoYU1Db3hGVEFUQmdOVkJBb1RESE5wWjNOMGIzSmxMbVJsZGpF
Uk1BOEdBMVVFQXhNSWMybG5jM1J2Y21Vd2RqQVFCZ2NxaGtqT1BRSUJCZ1VyZ1FRQUlnTmlBQVQ3
WGVGVDRyYjNQUUd3UzRJYWp0TGszL09sbnBnYW5nYUJjbFlwc1lCcjVpKzR5bkIwN2NlYjNMUDBP
SU9aZHhleFg2OWM1aVZ1eUpSUStIejA1eWkrVUYzdUJXQWxIcGlTNXNoMCtIMkdIRTdTWHJrMUVD
NW0xVHIxOUw5Z2c5MmpZekJoTUE0R0ExVWREd0VCL3dRRUF3SUJCakFQQmdOVkhSTUJBZjhFQlRB
REFRSC9NQjBHQTFVZERnUVdCQlJZd0I1ZmtVV2xacWw2ekpDaGt5TFFLc1hGK2pBZkJnTlZIU01F
R0RBV2dCUll3QjVma1VXbFpxbDZ6SkNoa3lMUUtzWEYrakFLQmdncWhrak9QUVFEQXdOcEFEQm1B
akVBajFuSGVYWnArMTNOV0JOYStFRHNEUDhHMVdXZzF0Q01XUC9XSFBxcGFWbzBqaHN3ZU5GWmdT
czBlRTd3WUk0cUFqRUEyV0I5b3Q5OHNJa29GM3ZaWWRkMy9WdFdCNWI5VE5NZWE3SXgvc3RKNVRm
Y0xMZUFCTEU0Qk5KT3NRNHZuQkhKIgogICAgICAgICAgfQogICAgICAgIF0KICAgICAgfSwKICAg
ICAgInZhbGlkRm9yIjogewogICAgICAgICJzdGFydCI6ICIyMDIyLTA0LTEzVDIwOjA2OjE1WiIK
ICAgICAgfQogICAgfQogIF0sCiAgImN0bG9ncyI6IFsKICAgIHsKICAgICAgImJhc2VVcmwiOiAi
aHR0cHM6Ly9jdGZlLnNpZ3N0b3JlLmRldi90ZXN0IiwKICAgICAgImhhc2hBbGdvcml0aG0iOiAi
U0hBMl8yNTYiLAogICAgICAicHVibGljS2V5IjogewogICAgICAgICJyYXdCeXRlcyI6ICJNRmt3
RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUViZndSK1JKdWRYc2NnUkJScEtYMVhGRHkz
UHl1ZER4ei9TZm5SaTFmVDhla3BmQmQyTzF1b3o3anIzWjhuS3p4QTY5RVVRK2VGQ0ZJM3pldWJQ
V1U3dz09IiwKICAgICAgICAia2V5RGV0YWlscyI6ICJQS0lYX0VDRFNBX1AyNTZfU0hBXzI1NiIs
CiAgICAgICAgInZhbGlkRm9yIjogewogICAgICAgICAgInN0YXJ0IjogIjIwMjEtMDMtMTRUMDA6
MDA6MDBaIiwKICAgICAgICAgICJlbmQiOiAiMjAyMi0xMC0zMVQyMzo1OTo1OS45OTlaIgogICAg
ICAgIH0KICAgICAgfSwKICAgICAgImxvZ0lkIjogewogICAgICAgICJrZXlJZCI6ICJDR0NTOENo
Uy8yaEYwZEZySjRTY1JXY1lyQlk5d3pqU2JlYThJZ1kyYjNJPSIKICAgICAgfQogICAgfSwKICAg
IHsKICAgICAgImJhc2VVcmwiOiAiaHR0cHM6Ly9jdGZlLnNpZ3N0b3JlLmRldi8yMDIyIiwKICAg
ICAgImhhc2hBbGdvcml0aG0iOiAiU0hBMl8yNTYiLAogICAgICAicHVibGljS2V5IjogewogICAg
ICAgICJyYXdCeXRlcyI6ICJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVpUFNs
RmkwQ21GVGZFakNVcUY5SHVDRWNZWE5LQWFZYWxJSm1CWjh5eWV6UGpUcWh4cktCcE1uYW9jVnRM
SkJJMWVNM3VYblF6UUdBSmRKNGdzOUZ5dz09IiwKICAgICAgICAia2V5RGV0YWlscyI6ICJQS0lY
X0VDRFNBX1AyNTZfU0hBXzI1NiIsCiAgICAgICAgInZhbGlkRm9yIjogewogICAgICAgICAgInN0
YXJ0IjogIjIwMjItMTAtMjBUMDA6MDA6MDBaIgogICAgICAgIH0KICAgICAgfSwKICAgICAgImxv
Z0lkIjogewogICAgICAgICJrZXlJZCI6ICIzVDB3YXNiSEVUSmpHUjRjbVdjM0FxSktYcmplUEsz
L2g0cHlnQzhwN280PSIKICAgICAgfQogICAgfQogIF0sCiAgInRpbWVzdGFtcEF1dGhvcml0aWVz
IjogWwogICAgewogICAgICAic3ViamVjdCI6IHsKICAgICAgICAib3JnYW5pemF0aW9uIjogInNp
Z3N0b3JlLmRldiIsCiAgICAgICAgImNvbW1vbk5hbWUiOiAic2lnc3RvcmUtdHNhLXNlbGZzaWdu
ZWQiCiAgICAgIH0sCiAgICAgICJ1cmkiOiAiaHR0cHM6Ly90aW1lc3RhbXAuc2lnc3RvcmUuZGV2
L2FwaS92MS90aW1lc3RhbXAiLAogICAgICAiY2VydENoYWluIjogewogICAgICAgICJjZXJ0aWZp
Y2F0ZXMiOiBbCiAgICAgICAgICB7CiAgICAgICAgICAgICJyYXdCeXRlcyI6ICJNSUlDRURDQ0Fa
YWdBd0lCQWdJVU9oTlVMd3lRWWU2OHdVTXZ5NHFPaXlvaml3d3dDZ1lJS29aSXpqMEVBd013T1RF
Vk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNU0F3SGdZRFZRUURFeGR6YVdkemRHOXlaUzEw
YzJFdGMyVnNabk5wWjI1bFpEQWVGdzB5TlRBME1EZ3dOalU1TkROYUZ3MHpOVEEwTURZd05qVTVO
RE5hTUM0eEZUQVRCZ05WQkFvVERITnBaM04wYjNKbExtUmxkakVWTUJNR0ExVUVBeE1NYzJsbmMz
UnZjbVV0ZEhOaE1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFNHJhMlo4aEtOaWcyVDlr
RmpDQVRvR0czMGpreStXUXYzQnpMK21LdmgxU0tOUi9Vd3V3c2ZOQ2c0c3J5b1lBZDhFNmlzb3ZW
QTNNNGFvTmRtOVFEaTUwWjhuVEV5dnFnZkRQdFRJd1hJdGZpVy9BRmYxVjd1d2tia0FvajB4eGNv
Mm93YURBT0JnTlZIUThCQWY4RUJBTUNCNEF3SFFZRFZSME9CQllFRkluOWVVT0h6OUJsUnNNQ1Jz
Y3NjMXQ5dE9zRE1COEdBMVVkSXdRWU1CYUFGSmpzQWU5L3UxSC8xSlVlYjRxSW1GTUhpYzYvTUJZ
R0ExVWRKUUVCL3dRTU1Bb0dDQ3NHQVFVRkJ3TUlNQW9HQ0NxR1NNNDlCQU1EQTJnQU1HVUNNRHRw
c1YvNkthTzBxeUYvVU1zWDJhU1VYS1FGZG9HVHB0UUdjMGZ0cTFjc3VsSFBHRzZkc215TU5kM0pC
K0czRVFJeEFPYWp2QmNqcEptS2I0TnYrMlRhb2o4VWM1K2I2aWg2RlhDQ0tyYVNxdXBlMDd6cXN3
TWNYSlRlMWNFeHZIdnZsdz09IgogICAgICAgICAgfSwKICAgICAgICAgIHsKICAgICAgICAgICAg
InJhd0J5dGVzIjogIk1JSUI5ekNDQVh5Z0F3SUJBZ0lVVjdmMEdMRE9vRXpJaDhMWFNXODBPSmlV
cDE0d0NnWUlLb1pJemowRUF3TXdPVEVWTUJNR0ExVUVDaE1NYzJsbmMzUnZjbVV1WkdWMk1TQXdI
Z1lEVlFRREV4ZHphV2R6ZEc5eVpTMTBjMkV0YzJWc1puTnBaMjVsWkRBZUZ3MHlOVEEwTURnd05q
VTVORE5hRncwek5UQTBNRFl3TmpVNU5ETmFNRGt4RlRBVEJnTlZCQW9UREhOcFozTjBiM0psTG1S
bGRqRWdNQjRHQTFVRUF4TVhjMmxuYzNSdmNtVXRkSE5oTFhObGJHWnphV2R1WldRd2RqQVFCZ2Nx
aGtqT1BRSUJCZ1VyZ1FRQUlnTmlBQVFVUU50ZlJUL291M1lBVGE2d0Iva0tUZTcwY2ZKd3lSSUJv
dk1udDhSY0pwaC9DT0U4MnV5UzZGbXBwTExMMVZCUEdjUGZwUVBZSk5Yeld3aThpY3doS1E2Vy9R
ZTJoM29lYkJiMkZIcHdOSkRxbytUTWFDL3RkZmt2L0VsSkI3MmpSVEJETUE0R0ExVWREd0VCL3dR
RUF3SUJCakFTQmdOVkhSTUJBZjhFQ0RBR0FRSC9BZ0VBTUIwR0ExVWREZ1FXQkJTWTdBSHZmN3RS
LzlTVkhtK0tpSmhUQjRuT3Z6QUtCZ2dxaGtqT1BRUURBd05wQURCbUFqRUF3R0VHcmZHWlIxY2Vu
MVI4L0RUVk1JOTQzTHNzWm1KUnREcC9pN1NmR0htR1JQNmdSYnVqOXZPSzNiNjdaMFFRQWpFQXVU
Mkg2NzNMUUVhSFRjeVFTWnJrcDRtWDdXd2ttRitzVmJrWVk1bVhOK1JNSDEzS1VFSEhPcUFTYWVt
WVdLL0UiCiAgICAgICAgICB9CiAgICAgICAgXQogICAgICB9LAogICAgICAidmFsaWRGb3IiOiB7
CiAgICAgICAgInN0YXJ0IjogIjIwMjUtMDctMDRUMDA6MDA6MDBaIgogICAgICB9CiAgICB9CiAg
XQp9Cg==
SIDECAR_TRUSTED_ROOT_EOF
}

# Pull the in-toto statement (JSON) out of a cosign DSSE bundle. The bundle is
# read after cosign has verified that exact file, so its payload is authenticated.
# Two on-disk shapes are accepted: v0.3 bundles (.dsseEnvelope.payload) and the
# legacy cosign bundle, whose whole envelope is base64 in base64Signature.
attestation_statement() {
    local bundle="$1" flat env_b64 stmt_b64
    flat=$(tr -d ' \t\r\n' < "$bundle")
    stmt_b64=$(printf '%s' "$flat" \
        | sed -nE 's/.*"payload":"([A-Za-z0-9+/=]+)".*/\1/p' | head -n 1)
    if [[ -z "$stmt_b64" ]]; then
        env_b64=$(printf '%s' "$flat" \
            | sed -nE 's/.*"base64Signature":"([A-Za-z0-9+/=]+)".*/\1/p' | head -n 1)
        [[ -n "$env_b64" ]] || return 0
        stmt_b64=$(printf '%s' "$env_b64" | base64 -d 2>/dev/null | tr -d ' \t\r\n' \
            | sed -nE 's/.*"payload":"([A-Za-z0-9+/=]+)".*/\1/p' | head -n 1)
    fi
    printf '%s' "$stmt_b64" | base64 -d 2>/dev/null | tr -d ' \t\r\n'
}

# Extract the byproduct SHA-256 for a named SBOM from a compact statement.
# Cosign re-serializes predicates through Go (sorted map keys), so accept
# either key order instead of assuming the one release-attest.sh emits.
sbom_byproduct_digest() {
    local stmt="$1" sbom_name="$2" digest
    digest=$(sed -nE \
        "s/.*\\{\"digest\":\\{\"sha256\":\"([0-9a-f]{64})\"\\},\"name\":\"sbom:cyclonedx-json:${sbom_name}\".*/\\1/p" \
        "$stmt" | head -n 1)
    if [[ -z "$digest" ]]; then
        digest=$(sed -nE \
            "s/.*\"name\":\"sbom:cyclonedx-json:${sbom_name}\",\"uri\":\"[^\"]*\",\"digest\":\\{\"sha256\":\"([0-9a-f]{64})\"\\}.*/\\1/p" \
            "$stmt" | head -n 1)
    fi
    printf '%s' "$digest"
}

# verify_release_materials DIR ARCHIVE REPO TAG COSIGN_BIN TRUSTED_ROOT
# Echoes the provenance source commit only after every check passes.
verify_release_materials() {
    local dir="$1" archive="$2" repo="$3" tag="$4" cosign_bin="$5" trusted_root="$6"
    local module="github.com/${repo}"

    local checksums="$dir/checksums.txt"
    local checksums_bundle="$dir/checksums.txt.bundle"
    local blob="$dir/$archive"
    local att_bundle="$dir/$archive.att.bundle"
    local sbom="$dir/$archive.sbom.cdx.json"
    local sbom_bundle="$dir/$archive.sbom.cdx.json.bundle"
    local f
    for f in "$checksums" "$checksums_bundle" "$blob" "$att_bundle" "$sbom" "$sbom_bundle"; do
        [[ -s "$f" ]] || { echo "missing release material: $(basename "$f")" >&2; return 11; }
    done

    # The commit is read from the (still untrusted) attestation payload first
    # and fed back as a certificate claim: cosign then proves the cert's
    # GitHub-workflow-SHA equals the signed predicate commit. A payload with a
    # swapped commit fails unless the swap is backed by a Fulcio certificate
    # for the same workflow run of the same tag -- which only GitHub can mint.
    local commit_claim
    commit_claim=$(attestation_statement "$att_bundle" \
        | sed -nE 's/.*"gitCommit":"([0-9a-f]{40})".*/\1/p' | head -n 1)
    [[ -n "$commit_claim" ]] || { echo "attestation pins no source commit" >&2; return 11; }

    # Identity claims pinned into the Fulcio certificate. A certificate for a
    # different issuer, repository, workflow, ref, trigger or workflow SHA
    # cannot satisfy these. They apply to every certificate-based verification
    # (checksums, attestation, SBOM); cosign rejects them for --key bundles.
    local -a id_args=()
    local -a key_args=()
    if [[ -n "${SIDECAR_VERIFY_KEY:-}" ]]; then
        # Test seam: verify against a local public key. Never used by real
        # installs (no SIDECAR_VERIFY_KEY is ever set by this script).
        key_args=(--key "$SIDECAR_VERIFY_KEY" --insecure-ignore-tlog)
    else
        id_args=(
            --certificate-identity "https://github.com/${repo}/.github/workflows/release.yml@refs/tags/${tag}"
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
            --certificate-github-workflow-repository "$repo"
            --certificate-github-workflow-name "Release"
            --certificate-github-workflow-ref "refs/tags/${tag}"
            --certificate-github-workflow-trigger "push"
            --certificate-github-workflow-sha "$commit_claim"
        )
        if [[ -n "${SIDECAR_CERT:-}" ]]; then
            # Test seam: Fulcio-equivalent PKI using a local CA (exercises the
            # exact certificate-claim enforcement with synthetic certificates).
            [[ -s "$SIDECAR_CERT" && -s "${SIDECAR_CERT_CHAIN:-}" ]] \
                || { echo "missing test certificate chain" >&2; return 11; }
            key_args=(--certificate "$SIDECAR_CERT" \
                --certificate-chain "$SIDECAR_CERT_CHAIN" \
                --insecure-ignore-tlog --insecure-ignore-sct)
        else
            [[ -s "$trusted_root" ]] || { echo "missing trusted root" >&2; return 11; }
            key_args=(--trusted-root "$trusted_root")
        fi
    fi

    local archive_sha
    archive_sha=$(sha256_file "$blob")

    # 1. Signed checksums, then the archive digest inside them.
    "$cosign_bin" verify-blob "${key_args[@]}" ${id_args[@]+"${id_args[@]}"} \
        --bundle "$checksums_bundle" "$checksums" >/dev/null 2>&1 \
        || { echo "checksums.txt signature verification failed" >&2; return 11; }
    awk -v name="$archive" -v sha="$archive_sha" \
        '$1 == sha && $2 == name {found = 1} END {exit !found}' "$checksums" \
        || { echo "archive digest absent from signed checksums.txt" >&2; return 11; }

    # 2. SLSA provenance attestation. --check-claims requires the attestation
    # subject digest to equal the downloaded archive.
    "$cosign_bin" verify-blob-attestation "${key_args[@]}" ${id_args[@]+"${id_args[@]}"} \
        --bundle "$att_bundle" --type slsaprovenance1 --check-claims "$blob" \
        >/dev/null 2>&1 \
        || { echo "provenance attestation verification failed" >&2; return 11; }

    local stmt="$dir/statement.decoded.json"
    attestation_statement "$att_bundle" > "$stmt"
    [[ -s "$stmt" ]] || { echo "could not decode provenance statement" >&2; return 11; }

    # The subject must name THIS archive and pin THIS digest. New-bundle
    # verification also enforces it via cosign --check-claims; the anchors make
    # it explicit and give legacy-bundle verification the same guarantee.
    local anchor
    for anchor in \
        "\"name\":\"${archive}\"" \
        "\"digest\":{\"sha256\":\"${archive_sha}\"}" \
        '"predicateType":"https://slsa.dev/provenance/v1"' \
        "\"repository\":\"https://github.com/${repo}\"" \
        "\"ref\":\"refs/tags/${tag}\"" \
        '"workflow":".github/workflows/release.yml"' \
        '"trigger":"push"' \
        "\"id\":\"https://github.com/${repo}/.github/workflows/release.yml@refs/tags/${tag}\""; do
        grep -Fq -- "$anchor" "$stmt" \
            || { echo "provenance anchor failed: ${anchor:0:72}" >&2; return 11; }
    done

    local commit
    commit=$(sed -nE 's/.*"gitCommit":"([0-9a-f]{40})".*/\1/p' "$stmt" | head -n 1)
    [[ -n "$commit" ]] || { echo "provenance pins no source commit" >&2; return 11; }

    # 3. Signed SBOM, cross-linked to the provenance byproduct digest.
    "$cosign_bin" verify-blob "${key_args[@]}" ${id_args[@]+"${id_args[@]}"} \
        --bundle "$sbom_bundle" "$sbom" >/dev/null 2>&1 \
        || { echo "SBOM signature verification failed" >&2; return 11; }

    local sbom_sha sbom_expected
    sbom_sha=$(sha256_file "$sbom")
    sbom_expected=$(sbom_byproduct_digest "$stmt" "$archive.sbom.cdx.json")
    [[ -n "$sbom_expected" && "$sbom_sha" == "$sbom_expected" ]] \
        || { echo "SBOM digest does not match provenance byproduct" >&2; return 11; }

    # Compact the authenticated SBOM before anchoring (it ships compact, but
    # never rely on whitespace surviving transport).
    local sbom_flat="$dir/sbom.flat.json"
    tr -d ' \t\r\n' < "$sbom" > "$sbom_flat"
    for anchor in \
        "\"component\":{\"type\":\"application\",\"name\":\"${module}\",\"version\":\"${tag}\",\"purl\":\"pkg:golang/${module}@${tag}\"" \
        "\"name\":\"sidecar:archive-sha256\",\"value\":\"${archive_sha}\"" \
        "\"name\":\"sidecar:source-commit\",\"value\":\"${commit}\"" \
        "\"type\":\"vcs\",\"url\":\"https://github.com/${repo}@${commit}\""; do
        grep -Fq -- "$anchor" "$sbom_flat" \
            || { echo "SBOM anchor failed: ${anchor:0:72}" >&2; return 11; }
    done

    echo "$commit"
}

# install_verified_sidecar REPO TAG
# Downloads, verifies, and only then extracts/installs. Codes documented above.
install_verified_sidecar() {
    local repo="$1" tag="$2"
    local os arch
    os=$(detect_os)
    arch=$(detect_arch)
    [[ -n "$os" && "$arch" != "unsupported" ]] || return 13

    local ver="${tag#v}"
    local archive="sidecar_${ver}_${os}_${arch}.tar.gz"
    local root="${SIDECAR_RELEASE_BASE_URL:-$SIDECAR_RELEASE_BASE_URL_DEFAULT}"
    local base="$root/$tag"

    local work
    work=$(mktemp -d)
    trap 'rm -rf "$work"' RETURN

    # The attestation is the provenance canary: 404 means a legacy release,
    # another failure means the network/service is unreachable.
    local st
    st=$(http_download "$base/$archive.att.bundle" "$work/$archive.att.bundle")
    case "$st" in
        notfound) return 10 ;;
        error) return 12 ;;
    esac

    local name
    for name in \
        "$archive" \
        "checksums.txt" \
        "checksums.txt.bundle" \
        "$archive.sbom.cdx.json" \
        "$archive.sbom.cdx.json.bundle"; do
        st=$(http_download "$base/$name" "$work/$name")
        if [[ "$st" != "ok" ]]; then
            [[ "$st" == "notfound" ]] && return 11
            return 12
        fi
    done

    local cosign_bin trusted_root commit
    cosign_bin=$(ensure_cosign "$work") || return 14
    trusted_root="$work/trusted_root.json"
    if [[ -z "${SIDECAR_VERIFY_KEY:-}" ]]; then
        write_trusted_root "$trusted_root" || return 14
    fi

    if ! commit=$(verify_release_materials \
        "$work" "$archive" "$repo" "$tag" "$cosign_bin" "$trusted_root"); then
        return 11
    fi

    # ---- ALL VERIFICATION PASSED. Only now are bytes extracted/copied. ----
    local stage="$work/stage"
    mkdir "$stage"
    tar -xzf "$work/$archive" -C "$stage" 2>/dev/null || return 11
    [[ -f "$stage/sidecar" && -x "$stage/sidecar" && ! -L "$stage/sidecar" ]] \
        || return 11

    local install_dir target staging
    install_dir="${SIDECAR_INSTALL_DIR:-$(resolve_install_dir)}"
    mkdir -p "$install_dir"
    target="$install_dir/sidecar"
    staging="$install_dir/.sidecar.staging.$$"
    trap 'rm -rf "$work"; rm -f "$staging"' RETURN
    cp "$stage/sidecar" "$staging" || return 11
    chmod 0755 "$staging" || return 11
    # Same-filesystem atomic replace; an existing target is untouched until
    # this instant, so any earlier failure leaves it byte-for-byte in place.
    mv -f "$staging" "$target" || return 11

    echo "$commit"
}

# Legacy path, reachable ONLY through the explicit --allow-legacy-binary flag.
# TLS-only integrity, exactly like the old installer, kept for emergencies.
install_legacy_sidecar() {
    local repo="$1" tag="$2"
    local os arch
    os=$(detect_os)
    arch=$(detect_arch)
    [[ -n "$os" && "$arch" != "unsupported" ]] || return 13

    local ver="${tag#v}"
    local archive="sidecar_${ver}_${os}_${arch}.tar.gz"
    local root="${SIDECAR_RELEASE_BASE_URL:-$SIDECAR_RELEASE_BASE_URL_DEFAULT}"
    local base="$root/$tag"

    local work
    work=$(mktemp -d)
    trap 'rm -rf "$work"' RETURN

    local st
    st=$(http_download "$base/$archive" "$work/$archive")
    [[ "$st" == "ok" ]] || { [[ "$st" == "notfound" ]] && return 10; return 12; }

    mkdir "$work/stage"
    tar -xzf "$work/$archive" -C "$work/stage" 2>/dev/null || return 11
    [[ -f "$work/stage/sidecar" && ! -L "$work/stage/sidecar" ]] || return 11

    local install_dir target staging
    install_dir="${SIDECAR_INSTALL_DIR:-$(resolve_install_dir)}"
    mkdir -p "$install_dir"
    target="$install_dir/sidecar"
    staging="$install_dir/.sidecar.staging.$$"
    trap 'rm -rf "$work"; rm -f "$staging"' RETURN
    cp "$work/stage/sidecar" "$staging" || return 11
    chmod 0755 "$staging"
    mv -f "$staging" "$target" || return 11
}

# Explicit source build. Requires a local Go toolchain; never selected
# implicitly after a verification failure.
install_sidecar_from_source() {
    local version="$1"
    command -v go >/dev/null 2>&1 || return 1
    GOWORK=off go install -ldflags "-X main.Version=${version}" \
        "github.com/marcus/sidecar/cmd/sidecar@${version}"
}

# Main installation flow
main() {
    # Try to get gum for better UI
    try_install_gum

    echo ""
    style_header "Sidecar Setup"
    echo ""

    # Detect current state
    GO_VERSION=$(get_go_version)
    TD_VERSION=$(get_td_version)
    SIDECAR_VERSION=$(get_sidecar_version)
    TMUX_VERSION=$(get_tmux_version)

    # Fetch latest versions
    echo "Checking latest versions..."
    LATEST_SIDECAR=$(get_latest_release "marcus/sidecar" || echo "")
    if ! $SIDECAR_ONLY; then
        LATEST_TD=$(get_latest_release "marcus/td" || echo "")
    fi

    # Show status table
    echo ""
    style_header "Current Status"
    echo "──────────────────────────────────────"

    # Go status
    if [[ -n "$GO_VERSION" ]]; then
        if version_gte "$GO_VERSION" "1.21"; then
            style_success "  Go:      ✓ $GO_VERSION"
        else
            style_warning "  Go:      ! $GO_VERSION (need 1.21+)"
        fi
    else
        echo "  Go:      - not installed (optional with binary install)"
    fi

    # td status
    if ! $SIDECAR_ONLY; then
        if [[ -n "$TD_VERSION" ]]; then
            if [[ -n "$LATEST_TD" && "$TD_VERSION" != "$LATEST_TD" ]]; then
                style_warning "  td:      ✓ $TD_VERSION -> $LATEST_TD available"
            else
                style_success "  td:      ✓ $TD_VERSION"
            fi
        else
            echo "  td:      - not installed"
        fi
    fi

    # sidecar status
    if [[ -n "$SIDECAR_VERSION" ]]; then
        if [[ -n "$LATEST_SIDECAR" && "$SIDECAR_VERSION" != "$LATEST_SIDECAR" ]]; then
            style_warning "  sidecar: ✓ $SIDECAR_VERSION -> $LATEST_SIDECAR available"
        else
            style_success "  sidecar: ✓ $SIDECAR_VERSION"
        fi
    else
        echo "  sidecar: - not installed"
    fi

    # tmux status
    if [[ -n "$TMUX_VERSION" ]]; then
        style_success "  tmux:    ✓ $TMUX_VERSION"
    else
        style_warning "  tmux:    - not installed (recommended)"
    fi

    echo "──────────────────────────────────────"
    echo ""

    # Tool selection (unless --sidecar-only)
    local install_td=false
    local install_sidecar=true

    if ! $SIDECAR_ONLY && ! $YES_FLAG; then
        local choice
        choice=$(choose "What would you like to install?" \
            "[Recommended] Both td and sidecar" \
            "sidecar only" \
            "td only")

        case "$choice" in
            *"Both"*) install_td=true; install_sidecar=true ;;
            *"sidecar only"*) install_td=false; install_sidecar=true ;;
            *"td only"*) install_td=true; install_sidecar=false ;;
        esac
    elif $SIDECAR_ONLY; then
        install_td=false
        install_sidecar=true
    else
        # --yes mode: install both by default
        install_td=true
        install_sidecar=true
    fi

    # Check Go (only required if binary download unavailable)
    local has_go=false
    if [[ -n "$GO_VERSION" ]] && version_gte "$GO_VERSION" "1.21"; then
        has_go=true
    fi

    if ! $has_go && [[ "$ARCH" == "unsupported" ]]; then
        echo ""
        style_error "No pre-built binary for your architecture and Go is not installed."
        echo "Please install Go 1.21+ and run this script again."
        exit 1
    fi

    if $has_go; then
        # Ensure go/bin is in PATH
        local go_bin
        go_bin=$(get_go_bin)

        if ! check_go_path; then
            echo ""
            style_warning "$go_bin is not in your PATH"
            echo ""

            local shell_rc
            shell_rc=$(get_shell_rc)

            local path_cmd
            local source_cmd
            if is_fish_shell; then
                path_cmd="fish_add_path -gm $go_bin"
                source_cmd="source $shell_rc"
            else
                path_cmd="export PATH=\"$go_bin:\$PATH\""
                source_cmd="source $shell_rc"
            fi

            echo "Will add to $shell_rc:"
            echo "  $path_cmd"
            echo ""

            if confirm "Add to PATH?"; then
                echo "" >> "$shell_rc"
                echo "$path_cmd" >> "$shell_rc"
                export PATH="$go_bin:$PATH"
                style_success "Added to $shell_rc"
                echo ""
                echo "Note: Run '$source_cmd' to apply in current shell."
            else
                echo ""
                echo "Please add $go_bin to your PATH manually."
                echo "  $path_cmd"
            fi
        fi
    fi

    # Check tmux
    if [[ -z "$TMUX_VERSION" ]]; then
        echo ""
        style_header "Interactive Terminal Support"
        echo "Sidecar uses tmux to support the interactive terminal mode."
        echo "You don't need to know how to use tmux!"
        echo "We just use it in the background to handle split panes."
        echo ""

        local tmux_install_cmd=""
        if command -v brew &> /dev/null; then
            tmux_install_cmd="brew install tmux"
        elif command -v apt &> /dev/null; then
            tmux_install_cmd="sudo apt update && sudo apt install -y tmux"
        elif command -v dnf &> /dev/null; then
            tmux_install_cmd="sudo dnf install -y tmux"
        elif command -v pacman &> /dev/null; then
            tmux_install_cmd="sudo pacman -S --noconfirm tmux"
        elif command -v zypper &> /dev/null; then
            tmux_install_cmd="sudo zypper install -y tmux"
        elif command -v apk &> /dev/null; then
            tmux_install_cmd="sudo apk add tmux"
        fi

        if [[ -n "$tmux_install_cmd" ]]; then
            echo "Will run:"
            echo "  $tmux_install_cmd"
            echo ""
            if confirm "Install tmux (recommended)?"; then
                spin "Installing tmux..." bash -c "$tmux_install_cmd"
                TMUX_VERSION=$(get_tmux_version)
            else
                echo ""
                style_warning "Skipping tmux. Interactive terminal features will be disabled."
            fi
        else
            style_warning "Could not detect package manager for tmux."
            echo "Please install tmux manually to enable interactive terminal features."
            echo "  macOS:         brew install tmux"
            echo "  Ubuntu/Debian: sudo apt install tmux"
            echo "  Fedora:        sudo dnf install tmux"
            echo "  Arch:          sudo pacman -S tmux"
        fi
    fi

    # Install td
    if $install_td; then
        echo ""
        if [[ -z "$TD_VERSION" ]] || $FORCE_FLAG || [[ "$TD_VERSION" != "$LATEST_TD" ]]; then
            local td_version="${LATEST_TD:-latest}"

            echo "Will run:"
            echo "  go install github.com/marcus/td@${td_version}"
            echo ""

            if confirm "Install td?"; then
                echo "Installing td (this may take a minute)..."
                go install "github.com/marcus/td@${td_version}"
                TD_VERSION=$(get_td_version)
                style_success "td installed: $TD_VERSION"
            fi
        else
            style_success "td is up to date ($TD_VERSION)"
        fi
    fi

    # Install sidecar
    if $install_sidecar; then
        echo ""
        local sc_version="${SIDECAR_VERSION_PIN:-${LATEST_SIDECAR:-latest}}"
        local pinned=false
        [[ -n "$SIDECAR_VERSION_PIN" ]] && pinned=true

        if $pinned || [[ -z "$SIDECAR_VERSION" ]] || $FORCE_FLAG || [[ "$SIDECAR_VERSION" != "$LATEST_SIDECAR" ]]; then
            if confirm "Install sidecar ${sc_version}?"; then
                if $BUILD_FROM_SOURCE; then
                    echo "Building sidecar ${sc_version} from source (explicit --build-from-source)..."
                    if install_sidecar_from_source "$sc_version"; then
                        SIDECAR_VERSION=$(get_sidecar_version)
                        style_success "sidecar installed from source: $SIDECAR_VERSION"
                    else
                        style_error "Source build failed. Go 1.21+ is required."
                    fi
                else
                    echo "Downloading and verifying sidecar ${sc_version}..."
                    local verified_commit verify_code
                    # set -e would exit on the non-zero status we must branch on.
                    set +e
                    verified_commit=$(install_verified_sidecar "$SIDECAR_REPO" "$sc_version")
                    verify_code=$?
                    set -e
                    case $verify_code in
                        0)
                            SIDECAR_VERSION=$(get_sidecar_version)
                            style_success "sidecar installed: $SIDECAR_VERSION"
                            echo "  provenance commit: ${verified_commit:0:12} (verified offline)"
                            ;;
                        10)
                            style_warning "sidecar ${sc_version} is a LEGACY release with no provenance."
                            echo "  Precompiled binaries are not installed for legacy releases by default."
                            echo "  Preferred: brew install (builds from source, verifies the formula SHA),"
                            echo "  or re-run with --build-from-source (requires Go 1.21+)."
                            if $ALLOW_LEGACY_BINARY; then
                                style_warning "  --allow-legacy-binary given: installing with TLS-only integrity."
                                if install_legacy_sidecar "$SIDECAR_REPO" "$sc_version"; then
                                    SIDECAR_VERSION=$(get_sidecar_version)
                                    style_warning "sidecar installed WITHOUT provenance verification: $SIDECAR_VERSION"
                                else
                                    style_error "Legacy binary installation failed."
                                fi
                            fi
                            ;;
                        11)
                            style_error "sidecar ${sc_version} FAILED supply-chain verification."
                            echo "  A release material is missing or was tampered with. Nothing was installed."
                            echo "  Do not retry over an untrusted network. Re-run with --build-from-source"
                            echo "  (requires Go 1.21+) only if you accept a source build explicitly."
                            ;;
                        12)
                            style_error "Verification materials for sidecar ${sc_version} could not be downloaded."
                            echo "  Refusing to install an unverified binary. Check your network and retry,"
                            echo "  or re-run with --build-from-source (requires Go 1.21+) to choose explicitly."
                            ;;
                        13)
                            style_error "No precompiled sidecar for your platform/architecture."
                            echo "  Re-run with --build-from-source (requires Go 1.21+)."
                            ;;
                        14)
                            style_error "The cosign verifier is unavailable and could not be bootstrapped."
                            echo "  Install cosign 2.0+ and retry, or re-run with --build-from-source."
                            ;;
                        *)
                            style_error "sidecar installation failed (code $verify_code); nothing was installed."
                            ;;
                    esac

                    # On legacy/failed precompiled installs, offer a source
                    # build ONLY as an explicit interactive choice. -y never
                    # implies it, and an already-handled --allow-legacy success
                    # is not repeated.
                    if [[ $verify_code -ne 0 ]] && ! $BUILD_FROM_SOURCE && \
                       { [[ $verify_code -ne 10 ]] || ! $ALLOW_LEGACY_BINARY; }; then
                        if [[ -n "$(get_go_version)" ]] && version_gte "$(get_go_version)" "1.21" && \
                           choose_source_build "Build sidecar ${sc_version} from source instead?"; then
                            echo "Building sidecar ${sc_version} from source..."
                            if install_sidecar_from_source "$sc_version"; then
                                SIDECAR_VERSION=$(get_sidecar_version)
                                style_success "sidecar installed from source: $SIDECAR_VERSION"
                            else
                                style_error "Source build failed."
                            fi
                        elif [[ $verify_code -eq 10 || $verify_code -eq 11 || $verify_code -eq 12 || $verify_code -eq 14 ]]; then
                            echo "  Homebrew: brew tap marcus/tap && brew install sidecar"
                            echo "  Releases: https://github.com/marcus/sidecar/releases"
                        fi
                    fi
                fi
            fi
        else
            style_success "sidecar is up to date ($SIDECAR_VERSION)"
        fi
    fi

    # Final verification
    echo ""
    echo "──────────────────────────────────────"
    style_header "Installation Complete"
    echo ""

    local all_good=true

    if $install_sidecar; then
        if command -v sidecar &> /dev/null; then
            style_success "  ✓ sidecar $(get_sidecar_version)"
        else
            style_error "  ✗ sidecar not found"
            all_good=false
        fi
    fi

    if [[ -n "$TMUX_VERSION" ]]; then
        style_success "  ✓ tmux $TMUX_VERSION"
    else
        style_warning "  ! tmux not found (interactive features disabled)"
    fi

    if $install_td; then
        if command -v td &> /dev/null; then
            style_success "  ✓ td $(get_td_version)"
        else
            style_error "  ✗ td not found"
            all_good=false
        fi
    fi

    echo ""

    if $all_good; then
        echo ""
        style_success "✓ Setup complete!"
        echo ""
        style_header "Getting Started"
        echo ""
        if $install_td; then
            echo "  1. cd into your project directory"
            echo "  2. Run 'td init' to initialize task tracking"
            echo "  3. Run 'sidecar' to launch the UI"
        else
            echo "  1. cd into your project directory"
            echo "  2. Run 'sidecar' to launch the UI"
        fi
        echo ""
    else
        echo "Some installations may have failed. Check the output above."
        echo "You may need to run 'source $(get_shell_rc)' to update your PATH."
    fi
}

# Run main, unless the script is being sourced for its functions (tests).
if [[ -z "${SIDECAR_SETUP_NO_MAIN:-}" ]]; then
    main
fi
