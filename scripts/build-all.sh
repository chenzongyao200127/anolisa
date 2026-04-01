#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# build-all.sh  –  ANOLISA unified build script
#
# Usage:
#   ./scripts/build-all.sh                                    # install deps + build + install (default)
#   ./scripts/build-all.sh --no-install                       # install deps + build, skip system install
#   ./scripts/build-all.sh --ignore-deps                      # build + install, skip dep install
#   ./scripts/build-all.sh --deps-only                        # install deps only
#   ./scripts/build-all.sh --component cosh                   # deps + build + install copilot-shell only
#   ./scripts/build-all.sh --help
#
# Components (build order):
#   cosh     copilot-shell      (Node.js / TypeScript)
#   skills   os-skills          (Markdown skill definitions, no compilation)
#   sec-core agent-sec-core     (Rust sandbox, Linux only)
#   sight    agentsight         (eBPF / Rust, Linux only, NOT built by default)
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

# ─── colors ───

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ─── paths ───

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ─── defaults ───

INSTALL_DEPS=true
DEPS_ONLY=false
DO_INSTALL=true
COMPONENTS=()        # empty = all

# ─── artifact tracking ───

ARTIFACT_NAMES=()
ARTIFACT_PATHS=()

# ─── helpers ───

info()  { echo -e "${BLUE}[info]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ok]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}  $*"; }
err()   { echo -e "${RED}[error]${NC} $*"; }
step()  { echo -e "\n${CYAN}${BOLD}==> $*${NC}"; }

cmd_exists() { command -v "$1" &>/dev/null; }

# Extract first semver (X.Y.Z) from a string.
# Examples: "rustc 1.91.0 (abc 2024)" -> "1.91.0", "v22.21.1" -> "22.21.1"
extract_ver() {
    echo "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

# ver_gte "1.91.0" "1.80.0" -> true (actual >= required)
ver_gte() {
    printf '%s\n%s' "$2" "$1" | sort -V -C
}

die() { err "$@"; exit 1; }

# ─── distro detection ───

DISTRO_ID=""        # alinux, ubuntu, fedora, centos, anolis, etc.
DISTRO_VER=""       # 4, 24.04, 9, etc.
DISTRO_VER_MAJOR="" # 4, 24, 9, etc.
PKG_BASE=""         # rpm | deb
PKG_INSTALL=""

detect_distro() {
    [[ -f /etc/os-release ]] || die "Cannot detect distro (no /etc/os-release). Linux only."
    # shellcheck source=/dev/null
    source /etc/os-release
    DISTRO_ID="${ID:-}"
    DISTRO_VER="${VERSION_ID:-}"
    DISTRO_VER_MAJOR="${DISTRO_VER%%.*}"
    local id_like="${ID_LIKE:-}"

    if [[ "$DISTRO_ID" =~ ^(fedora|rhel|centos|anolis|alinux)$ ]] || [[ "$id_like" =~ (fedora|rhel) ]]; then
        PKG_BASE="rpm"
        if cmd_exists dnf; then PKG_INSTALL="dnf install -y"
        elif cmd_exists yum; then PKG_INSTALL="yum install -y"
        else die "Neither dnf nor yum found"; fi
    elif [[ "$DISTRO_ID" =~ ^(debian|ubuntu)$ ]] || [[ "$id_like" =~ debian ]]; then
        PKG_BASE="deb"
        PKG_INSTALL="apt-get install -y"
    else
        die "Unsupported distro: ${PRETTY_NAME:-$DISTRO_ID}. Supported: Fedora/RHEL/CentOS/Anolis/Alinux, Debian/Ubuntu."
    fi

    ok "Distro: ${PRETTY_NAME:-$DISTRO_ID} (${PKG_BASE}, id=${DISTRO_ID}, ver=${DISTRO_VER})"
}

# ─── component helpers ───

# Default components (sight is excluded — it is optional and provides audit
# capabilities only; use --component sight to include it explicitly).
DEFAULT_COMPONENTS=(cosh skills sec-core)

want_component() {
    local c="$1"
    if [[ ${#COMPONENTS[@]} -eq 0 ]]; then
        # No explicit --component flags: use default list
        local d
        for d in "${DEFAULT_COMPONENTS[@]}"; do
            if [[ "$d" == "$c" ]]; then return 0; fi
        done
        return 1
    fi
    local x
    for x in "${COMPONENTS[@]}"; do
        if [[ "$x" == "$c" ]]; then return 0; fi
    done
    return 1
}

# ─── dependency installation ───

# Query the highest version of a package available in the configured system repositories.
# Prints semver string (e.g. "20.18.0") or nothing if the package is not found.
query_repo_ver() {
    local pkg="$1"
    if [[ "$PKG_BASE" == "rpm" ]]; then
        # dnf list output example: "nodejs.x86_64    1:20.18.0-1.alnx4    appstream"
        local raw
        raw=$(dnf list "$pkg" 2>/dev/null | grep -E "^${pkg}\." | tail -1)
        [[ -z "$raw" ]] && raw=$(yum list "$pkg" 2>/dev/null | grep -E "^${pkg}\." | tail -1)
        if [[ -n "$raw" ]]; then
            local nvr
            nvr=$(echo "$raw" | awk '{print $2}')
            nvr="${nvr#*:}"   # strip epoch (e.g. "1:20.18.0-1" → "20.18.0-1")
            extract_ver "$nvr"
            return
        fi
    elif [[ "$PKG_BASE" == "deb" ]]; then
        # apt-cache policy output: "  Candidate: 18.19.0+dfsg-6ubuntu5"
        local candidate
        candidate=$(apt-cache policy "$pkg" 2>/dev/null | sed -n 's/.*Candidate: *//p')
        if [[ -n "$candidate" && "$candidate" != "(none)" ]]; then
            extract_ver "$candidate"
            return
        fi
    fi
}

install_node() {
    step "Node.js (for copilot-shell)"
    local REQUIRED="20.0.0"

    # 1. Already installed and meets requirement?
    if cmd_exists node; then
        local ver
        ver=$(extract_ver "$(node -v 2>/dev/null)" || echo "")
        if [[ -n "$ver" ]] && ver_gte "$ver" "$REQUIRED"; then
            ok "Node.js $(node -v) already installed, skipping"
            return 0
        fi
        warn "Node.js $ver is too old (need >= 20)"
    fi

    # 2. Check if system repository provides a suitable version
    local repo_ver
    repo_ver=$(query_repo_ver nodejs)
    if [[ -n "$repo_ver" ]] && ver_gte "$repo_ver" "$REQUIRED"; then
        info "Repository provides nodejs $repo_ver (meets >= $REQUIRED), installing via package manager ..."
        if [[ "$PKG_BASE" == "deb" ]]; then sudo apt-get update -y 2>/dev/null || true; fi
        sudo $PKG_INSTALL nodejs npm || true
        if cmd_exists node; then
            local ver
            ver=$(extract_ver "$(node -v 2>/dev/null)" || echo "")
            if [[ -n "$ver" ]] && ver_gte "$ver" "$REQUIRED"; then
                ok "Node.js $(node -v) installed via system package manager"
                return 0
            fi
        fi
        warn "Package install did not satisfy version requirement, falling back to nvm"
    else
        info "Repository nodejs${repo_ver:+ $repo_ver} does not meet >= $REQUIRED, using nvm"
    fi

    # 3. Fallback: install via nvm
    _install_node_via_nvm
}

_install_node_via_nvm() {
    # Ensure shell rc file exists
    if [[ -f "$HOME/.zshrc" ]]; then
        touch "$HOME/.zshrc"
    else
        touch "$HOME/.bashrc"
    fi

    if ! cmd_exists nvm; then
        info "Installing nvm ..."
        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash

        export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
        # shellcheck source=/dev/null
        [[ -s "$NVM_DIR/nvm.sh" ]] && source "$NVM_DIR/nvm.sh"
    fi

    # nvm is a shell function — try sourcing if not found
    if ! cmd_exists nvm; then
        export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
        # shellcheck source=/dev/null
        [[ -s "$NVM_DIR/nvm.sh" ]] && source "$NVM_DIR/nvm.sh"
    fi

    info "Installing Node.js 20 via nvm ..."
    nvm install 20
    nvm use 20

    ok "Node.js $(node -v), npm $(npm -v)"
}

install_build_tools() {
    step "Build tools (make, g++)"

    local missing=()
    if ! cmd_exists make; then missing+=("make"); fi

    if [[ "$PKG_BASE" == "rpm" ]]; then
        if ! cmd_exists g++; then missing+=("gcc-c++"); fi
    else
        if ! cmd_exists g++; then missing+=("g++"); fi
    fi

    if [[ ${#missing[@]} -eq 0 ]]; then
        ok "Build tools already installed, skipping"
        return 0
    fi

    info "Installing: ${missing[*]}"
    # shellcheck disable=SC2086
    sudo $PKG_INSTALL "${missing[@]}"
    ok "Build tools installed"
}

install_rust() {
    step "Rust (for agent-sec-core, agentsight)"
    local REQUIRED="1.91.0"

    # 1. Already installed and meets requirement?
    if cmd_exists rustc && cmd_exists cargo; then
        local ver
        ver=$(extract_ver "$(rustc --version 2>/dev/null)" || echo "")
        if [[ -n "$ver" ]] && ver_gte "$ver" "$REQUIRED"; then
            ok "Rust $ver already installed, skipping"
            return 0
        fi
        warn "Rust $ver is too old (need >= 1.91)"
        if cmd_exists rustup; then
            info "Updating via rustup ..."
            rustup update stable
            ver=$(extract_ver "$(rustc --version 2>/dev/null)" || echo "")
            if [[ -n "$ver" ]] && ver_gte "$ver" "$REQUIRED"; then
                ok "Rust updated to $ver via rustup"
                return 0
            fi
        fi
    fi

    # 2. Check if system repository provides a suitable version
    local rust_pkg="" cargo_pkg="" repo_ver=""

    if [[ "$PKG_BASE" == "rpm" ]]; then
        rust_pkg="rust"; cargo_pkg="cargo"
        repo_ver=$(query_repo_ver rust)
    elif [[ "$PKG_BASE" == "deb" ]]; then
        rust_pkg="rustc"; cargo_pkg="cargo"
        repo_ver=$(query_repo_ver rustc)

        # DEB repos may ship versioned packages (rustc-1.XX) — pick the best one
        if [[ -z "$repo_ver" ]] || ! ver_gte "$repo_ver" "$REQUIRED"; then
            local best_pkg="" best_ver="" p pv
            while IFS= read -r p; do
                [[ -z "$p" ]] && continue
                pv=$(query_repo_ver "$p")
                [[ -z "$pv" ]] && continue
                if ver_gte "$pv" "$REQUIRED"; then
                    if [[ -z "$best_ver" ]] || ver_gte "$pv" "$best_ver"; then
                        best_pkg="$p"; best_ver="$pv"
                    fi
                fi
            done < <(apt-cache search '^rustc-[0-9]' 2>/dev/null | awk '{print $1}' | sort -V)
            if [[ -n "$best_pkg" ]]; then
                rust_pkg="$best_pkg"
                cargo_pkg="${best_pkg/rustc/cargo}"
                repo_ver="$best_ver"
            fi
        fi
    fi

    if [[ -n "$repo_ver" ]] && ver_gte "$repo_ver" "$REQUIRED"; then
        info "Repository provides $rust_pkg $repo_ver (meets >= $REQUIRED), installing via package manager ..."
        sudo $PKG_INSTALL "$rust_pkg" "$cargo_pkg" gcc make || true

        # For versioned DEB packages (e.g. rustc-1.91), set up alternatives
        if [[ "$PKG_BASE" == "deb" && "$rust_pkg" != "rustc" ]]; then
            local suffix="${rust_pkg#rustc-}"   # "1.91"
            if cmd_exists update-alternatives; then
                sudo update-alternatives --install /usr/bin/rustc rustc "/usr/bin/rustc-${suffix}" 100 2>/dev/null || true
                sudo update-alternatives --install /usr/bin/cargo cargo "/usr/bin/cargo-${suffix}" 100 2>/dev/null || true
            fi
        fi

        if cmd_exists rustc && cmd_exists cargo; then
            local ver
            ver=$(extract_ver "$(rustc --version 2>/dev/null)" || echo "")
            if [[ -n "$ver" ]] && ver_gte "$ver" "$REQUIRED"; then
                ok "Rust $ver installed via system package manager"
                info "Note: agent-sec-core pins Rust 1.93.0 via rust-toolchain.toml; rustup will auto-download if needed"
                return 0
            fi
        fi
        warn "Package install did not satisfy version requirement, falling back to rustup"
    else
        info "Repository rust${repo_ver:+ $repo_ver} does not meet >= $REQUIRED, using rustup"
    fi

    # 3. Fallback: install via rustup
    _install_rust_via_rustup
}

_install_rust_via_rustup() {
    info "Installing rustup + stable toolchain ..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"

    ok "Rust $(extract_ver "$(rustc --version)"), cargo $(extract_ver "$(cargo --version)")"
}

install_uv() {
    step "uv (Python package manager, for agent-sec-core)"

    if cmd_exists uv; then
        ok "uv $(extract_ver "$(uv --version 2>/dev/null)") already installed, skipping"
        return 0
    fi

    # Try pip3 (commonly available on rpm-based systems)
    if cmd_exists pip3; then
        info "Trying: pip3 install uv ..."
        pip3 install uv 2>/dev/null || true
        if cmd_exists uv; then
            ok "uv $(extract_ver "$(uv --version 2>/dev/null)") installed via pip3"
            return 0
        fi
    fi

    # Try pipx (install it first if not present)
    if ! cmd_exists pipx; then
        info "Trying to install pipx via package manager ..."
        sudo $PKG_INSTALL pipx 2>/dev/null || true
    fi
    if cmd_exists pipx; then
        info "Trying: pipx install uv ..."
        pipx ensurepath 2>/dev/null || true
        export PATH="$HOME/.local/bin:$PATH"
        pipx install uv 2>/dev/null || true
        if cmd_exists uv; then
            ok "uv $(extract_ver "$(uv --version 2>/dev/null)") installed via pipx"
            return 0
        fi
    fi

    # Fallback: install via upstream installer
    _install_uv_via_curl
}

_install_uv_via_curl() {
    info "Installing uv via upstream installer ..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # Source the env so uv is available in current session
    if [[ -f "$HOME/.local/bin/env" ]]; then
        # shellcheck source=/dev/null
        source "$HOME/.local/bin/env"
    fi
    export PATH="$HOME/.local/bin:$PATH"

    ok "uv $(extract_ver "$(uv --version 2>/dev/null)")"
}

check_ebpf_deps() {
    step "eBPF dependencies (for agentsight)"

    info "AgentSight requires clang, llvm, and libbpf headers from your system package manager."

    local missing=()

    if ! cmd_exists clang; then missing+=("clang"); fi
    if ! cmd_exists llvm-config && ! cmd_exists llvm-config-*; then missing+=("llvm"); fi

    if [[ "$PKG_BASE" == "rpm" ]]; then
        local pkgs=("libbpf-devel" "elfutils-libelf-devel" "zlib-devel" "openssl-devel" "perl" "perl-core" "perl-IPC-Cmd")
        local pkg
        for pkg in "${pkgs[@]}"; do
            if ! rpm -q "$pkg" &>/dev/null; then
                missing+=("$pkg")
            fi
        done

        if [[ ${#missing[@]} -eq 0 ]]; then
            ok "All eBPF packages present"
        else
            warn "Missing eBPF packages: ${missing[*]}"
            info "Install with: ${BOLD}sudo dnf install -y ${missing[*]}${NC}"

            if $INSTALL_DEPS; then
                info "Installing missing eBPF packages ..."
                # shellcheck disable=SC2086
                sudo $PKG_INSTALL "${missing[@]}"
                ok "eBPF packages installed"
            fi
        fi

    elif [[ "$PKG_BASE" == "deb" ]]; then
        local pkgs=("libbpf-dev" "libelf-dev" "zlib1g-dev" "libssl-dev" "perl")
        local kver
        kver=$(uname -r 2>/dev/null || echo "")
        if [[ -n "$kver" ]]; then
            pkgs+=("linux-headers-${kver}")
        fi
        local pkg
        for pkg in "${pkgs[@]}"; do
            if ! dpkg -s "$pkg" &>/dev/null 2>&1; then
                missing+=("$pkg")
            fi
        done

        if [[ ${#missing[@]} -eq 0 ]]; then
            ok "All eBPF packages present"
        else
            warn "Missing eBPF packages: ${missing[*]}"
            info "Install with: ${BOLD}sudo apt-get install -y ${missing[*]}${NC}"

            if $INSTALL_DEPS; then
                info "Updating package index ..."
                sudo apt-get update -y
                info "Installing missing eBPF packages ..."
                sudo $PKG_INSTALL "${missing[@]}"
                ok "eBPF packages installed"
            fi
        fi
    fi

    # Kernel BTF check
    if [[ -f /sys/kernel/btf/vmlinux ]]; then
        ok "Kernel BTF support available"
    else
        warn "Kernel BTF not found (/sys/kernel/btf/vmlinux). agentsight requires CONFIG_DEBUG_INFO_BTF=y"
    fi
}

# ─── top-level dep installer ───

do_install_deps() {
    step "Detecting system"
    detect_distro

    if want_component cosh; then
        install_node
        install_build_tools
    fi

    if want_component sec-core || want_component sight; then
        install_rust
    fi

    if want_component sec-core; then
        install_uv
    fi

    if want_component sight; then
        check_ebpf_deps
    fi

    echo ""
    ok "Dependency setup complete"
}

# ─── build functions ───

build_cosh() {
    step "Building copilot-shell"
    local dir="$PROJECT_ROOT/src/copilot-shell"
    [[ -d "$dir" ]] || die "Directory not found: $dir"
    cd "$dir"

    info "npm install ..."
    npm install

    info "npm run build ..."
    npm run build

    info "npm run bundle ..."
    npm run bundle

    if [[ -f dist/cli.js ]]; then
        ARTIFACT_NAMES+=("copilot-shell")
        ARTIFACT_PATHS+=("src/copilot-shell/dist/cli.js")
        ok "copilot-shell built successfully"
    else
        warn "Expected artifact dist/cli.js not found"
    fi
}

build_skills() {
    step "Installing os-skills"
    local dir="$PROJECT_ROOT/src/os-skills"
    [[ -d "$dir" ]] || die "Directory not found: $dir"
    cd "$dir"

    local count=0
    count=$(find . -name "SKILL.md" 2>/dev/null | wc -l)
    count=$((count + 0)) # trim whitespace

    info "Found ${count} skill definitions"

    # Deploy to user-level skill path
    local target="$HOME/.copilot/skills"
    mkdir -p "$target"

    info "Copying skills to $target ..."
    find . -name 'SKILL.md' -exec sh -c \
        'cp -rp "$(dirname "$1")" "'"$target"'/"' _ {} \;

    ARTIFACT_NAMES+=("os-skills")
    ARTIFACT_PATHS+=("~/.copilot/skills/ (${count} skills installed)")
    ok "os-skills: ${count} skills deployed to $target"
}

build_sec_core() {
    step "Building agent-sec-core (linux-sandbox)"
    local dir="$PROJECT_ROOT/src/agent-sec-core"
    [[ -d "$dir" ]] || die "Directory not found: $dir"
    cd "$dir"

    info "cargo build --release (linux-sandbox) ..."
    if [[ -f Makefile ]] && grep -q 'build-sandbox' Makefile; then
        make build-sandbox
    else
        cd linux-sandbox && cargo build --release && cd ..
    fi

    local bin="linux-sandbox/target/release/linux-sandbox"
    if [[ -f "$bin" ]]; then
        ARTIFACT_NAMES+=("agent-sec-core")
        ARTIFACT_PATHS+=("src/agent-sec-core/$bin")
        ok "agent-sec-core built successfully"
    else
        warn "Expected artifact $bin not found"
    fi
}

build_sight() {
    step "Building agentsight"
    local dir="$PROJECT_ROOT/src/agentsight"
    [[ -d "$dir" ]] || die "Directory not found: $dir"
    cd "$dir"

    info "cargo build --release ..."
    if [[ -f Makefile ]] && grep -q 'build' Makefile; then
        make build
    else
        cargo build --release
    fi

    local bin="target/release/agentsight"
    if [[ -f "$bin" ]]; then
        ARTIFACT_NAMES+=("agentsight")
        ARTIFACT_PATHS+=("src/agentsight/$bin")
        ok "agentsight built successfully"
    else
        warn "Expected artifact $bin not found"
    fi
}

do_build() {
    # Fixed build order: cosh -> skills -> sec-core -> sight (sight only if explicitly requested)
    if want_component cosh;     then build_cosh;     fi
    if want_component skills;   then build_skills;   fi
    if want_component sec-core; then build_sec_core; fi
    if want_component sight;    then build_sight;    fi
}

# ─── install functions ───

install_cosh() {
    step "Installing copilot-shell (create aliases)"
    local dir="$PROJECT_ROOT/src/copilot-shell"
    [[ -d "$dir" ]] || die "Directory not found: $dir"
    cd "$dir"

    make create-alias
    ok "copilot-shell aliases configured"
}

install_sec_core() {
    step "Installing agent-sec-core"
    local dir="$PROJECT_ROOT/src/agent-sec-core"
    [[ -d "$dir" ]] || die "Directory not found: $dir"
    cd "$dir"

    info "sudo make install ..."
    sudo make install
    ok "agent-sec-core installed to /usr/local/bin/"
}

install_sight() {
    step "Installing agentsight"
    local dir="$PROJECT_ROOT/src/agentsight"
    [[ -d "$dir" ]] || die "Directory not found: $dir"
    cd "$dir"

    info "sudo make install ..."
    sudo make install
    ok "agentsight installed to /usr/local/bin/"
}

do_install() {
    step "Installing components"
    if want_component cosh;     then install_cosh;     fi
    # skills are deployed during build, no separate install needed
    if want_component sec-core; then install_sec_core; fi
    if want_component sight;    then install_sight;    fi
}

print_artifacts() {
    step "Artifacts"

    if [[ ${#ARTIFACT_NAMES[@]} -eq 0 ]]; then
        warn "No artifacts produced"
        return 0
    fi

    local i
    for (( i=0; i<${#ARTIFACT_NAMES[@]}; i++ )); do
        echo -e "  ${GREEN}${ARTIFACT_NAMES[$i]}${NC}  ->  ${ARTIFACT_PATHS[$i]}"
    done

    echo ""
    info "Paths are relative to: $PROJECT_ROOT"
}

# ─── usage ───

usage() {
    cat <<EOF
$(echo -e "${BOLD}ANOLISA Build Script${NC}")

$(echo -e "${BOLD}Usage:${NC}")
  $0 [OPTIONS]

$(echo -e "${BOLD}Options:${NC}")
  --no-install            Skip installing built components to system paths
  --ignore-deps           Skip dependency installation
  --deps-only             Install dependencies only, do not build
  --component <name>      Build specific component (can be repeated).
                          Valid names: cosh, skills, sec-core, sight
                          Default (no --component): cosh, skills, sec-core
                          (sight is optional and must be explicitly requested)
  -h, --help              Show this help

$(echo -e "${BOLD}Examples:${NC}")
  $0                                             # Install deps + build + install to system
  $0 --no-install                                # Install deps + build (skip system install)
  $0 --ignore-deps                               # Build + install (skip dep install)
  $0 --deps-only                                 # Install deps only
  $0 --component cosh                            # Install deps + build + install copilot-shell
  $0 --ignore-deps --component sec-core --component sight
                                                 # Build + install sec-core and sight (no dep install)

$(echo -e "${BOLD}Components:${NC}")
  cosh     copilot-shell      Node.js / TypeScript AI terminal assistant       [default]
  skills   os-skills          Markdown skill definitions (deploy only)          [default]
  sec-core agent-sec-core     Rust secure sandbox (Linux only)                  [default]
  sight    agentsight         eBPF observability/audit agent (Linux only)        [optional]

$(echo -e "${BOLD}What this script does:${NC}")
  1. Detects installed toolchains and queries system repositories for available versions
  2. Installs via system package manager (dnf/yum/apt) when repository versions meet requirements
  3. Falls back to upstream installers (nvm, rustup, uv) when system packages don't suffice
  4. Builds default components in order: cosh -> skills -> sec-core
     (sight is optional — add --component sight to include it)
  5. Installs components to system paths (use --no-install to skip)
  6. Reports artifact locations at the end

$(echo -e "${BOLD}Note:${NC}")
  For agentsight eBPF probes, clang and libbpf headers must be installed via your
  system package manager. The script will detect and warn if they are missing.
EOF
    exit 0
}

# ─── argument parsing ───

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --no-install)
                DO_INSTALL=false
                shift
                ;;
            --ignore-deps)
                INSTALL_DEPS=false
                shift
                ;;
            --deps-only)
                DEPS_ONLY=true
                INSTALL_DEPS=true
                shift
                ;;
            --component)
                [[ -n "${2:-}" ]] || die "--component requires a value (cosh, skills, sec-core, sight)"
                case "$2" in
                    cosh|skills|sec-core|sight) COMPONENTS+=("$2") ;;
                    *) die "Unknown component: $2. Valid: cosh, skills, sec-core, sight" ;;
                esac
                shift 2
                ;;
            -h|--help)
                usage
                ;;
            *)
                die "Unknown option: $1. Use --help for usage."
                ;;
        esac
    done

    # --deps-only implies INSTALL_DEPS regardless of --ignore-deps
    if $DEPS_ONLY; then
        INSTALL_DEPS=true
    fi
}

# ─── main ───

main() {
    parse_args "$@"

    echo -e "${BOLD}ANOLISA Build Script${NC}"
    echo -e "${DIM}Project root: ${PROJECT_ROOT}${NC}"

    # 1. Install dependencies if requested
    if $INSTALL_DEPS; then
        do_install_deps
    fi

    # 2. Deps-only mode stops here
    if $DEPS_ONLY; then
        echo ""
        info "Deps-only mode, skipping build."
        exit 0
    fi

    # 3. Build
    do_build
    print_artifacts

    # 4. Install to system paths if requested
    if $DO_INSTALL; then
        do_install
    fi

    echo ""
    ok "Done"
}

main "$@"
