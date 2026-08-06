#!/usr/bin/env bash
# ─── Horus Server Installer ──────────────────────────────────────────────────
# One-time setup for a fresh Linux server.
#
# Usage:
#   bash scripts/server-install.sh
#
# What it does:
#   1. Adds current user to the docker group
#   2. Clones (or updates) the Horus repo to /opt/horus
#   3. Installs the `horus` management CLI at /usr/local/bin/horus
#   4. Creates .env from .env.sample (if not present)
#   5. Builds and starts Horus via Docker Compose
#
# Requires: sudo (for docker group + /opt + /usr/local/bin)
#           git, docker, docker compose

set -euo pipefail

REPO_URL="${HORUS_REPO_URL:-https://github.com/yusif-v/Horus.git}"
INSTALL_DIR="${HORUS_DIR:-/opt/horus}"
BRANCH="${HORUS_BRANCH:-main}"
CLI_BIN="/usr/local/bin/horus"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[install]${NC} $*"; }
warn() { echo -e "${YELLOW}[install]${NC} $*"; }
err()  { echo -e "${RED}[install]${NC} $*" >&2; exit 1; }

# ── Preflight ─────────────────────────────────────────────────────────────────

check_prerequisites() {
    for cmd in git docker; do
        command -v "$cmd" &>/dev/null || err "$cmd is required but not installed."
    done
    docker compose version &>/dev/null || err "Docker Compose V2 is required. Install: https://docs.docker.com/compose/install/"
    log "Prerequisites OK (git $(git --version | cut -d' ' -f3), docker $(docker --version | cut -d' ' -f3 | tr -d ','))"
}

ensure_docker_group() {
    if groups | grep -q docker; then
        log "User already in docker group."
        return
    fi
    log "Adding $USER to docker group (requires sudo)..."
    sudo usermod -aG docker "$USER"
    warn "Added to docker group. To apply without logout, this script uses 'newgrp docker' for remaining commands."
    # Re-exec this script under newgrp so remaining docker calls work
    if [[ "${_DOCKER_GROUP_APPLIED:-}" != "1" ]]; then
        export _DOCKER_GROUP_APPLIED=1
        exec newgrp docker <<EOF
export _DOCKER_GROUP_APPLIED=1
bash "$0" "$@"
EOF
    fi
}

# ── Clone / Update Repo ───────────────────────────────────────────────────────

setup_repo() {
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        log "Repo already cloned at $INSTALL_DIR. Pulling latest..."
        sudo git -C "$INSTALL_DIR" fetch origin
        sudo git -C "$INSTALL_DIR" checkout "$BRANCH"
        sudo git -C "$INSTALL_DIR" pull origin "$BRANCH"
        sudo chown -R "$USER:$USER" "$INSTALL_DIR"
    else
        log "Cloning Horus from $REPO_URL → $INSTALL_DIR ..."
        sudo mkdir -p "$INSTALL_DIR"
        sudo chown "$USER:$USER" "$INSTALL_DIR"
        git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
    fi
    log "Repo ready at $INSTALL_DIR"
}

# ── Install CLI ───────────────────────────────────────────────────────────────

install_cli() {
    log "Installing horus CLI at $CLI_BIN ..."
    sudo install -m 755 "$INSTALL_DIR/scripts/horus" "$CLI_BIN"
    log "horus CLI installed: $(which horus)"
}

# ── Configure .env ────────────────────────────────────────────────────────────

setup_env() {
    local env_file="$INSTALL_DIR/.env"
    if [[ -f "$env_file" ]]; then
        log ".env already exists — skipping (run 'horus config' to edit)."
        return
    fi
    if [[ -f "$INSTALL_DIR/.env.sample" ]]; then
        cp "$INSTALL_DIR/.env.sample" "$env_file"
        log ".env created from .env.sample"
        warn "Edit $env_file to configure tokens, sources, etc."
        warn "  You can do this now with: nano $env_file"
        warn "  Or after install with:    horus config"
    else
        err ".env.sample not found in $INSTALL_DIR"
    fi
}

# ── Deploy ────────────────────────────────────────────────────────────────────

do_deploy() {
    cd "$INSTALL_DIR"
    log "Building and starting Horus..."
    bash scripts/deploy.sh
}

# ── Summary ───────────────────────────────────────────────────────────────────

print_summary() {
    local ip
    ip=$(hostname -I | awk '{print $1}')
    local port
    port=$(grep -E '^HORUS_HOST_PORT=' "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "8081")
    port="${port:-8081}"

    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Horus installed successfully!${NC}"
    echo ""
    echo -e "  Web UI:      http://${ip}:${port}"
    echo -e "  Health:      http://${ip}:${port}/api/health"
    echo -e "  Install dir: ${INSTALL_DIR}"
    echo ""
    echo -e "  Management commands:"
    echo -e "    horus update    # pull latest + rebuild + restart"
    echo -e "    horus status    # container status"
    echo -e "    horus logs      # tail logs"
    echo -e "    horus stop      # stop"
    echo -e "    horus config    # edit .env"
    echo -e "    horus health    # check health endpoint"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────

log "Starting Horus server installation..."
check_prerequisites
ensure_docker_group
setup_repo
install_cli
setup_env
do_deploy
print_summary
