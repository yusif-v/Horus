#!/usr/bin/env bash
# ─── Horus Deploy Script ──────────────────────────────────────────────────────
# Deploy Horus to any server with Docker.
#
# Usage:
#   ./scripts/deploy.sh              # full deploy (build + start)
#   ./scripts/deploy.sh --update     # rebuild and restart
#   ./scripts/deploy.sh --stop      # stop and remove containers
#   ./scripts/deploy.sh --status    # show container status
#   ./scripts/deploy.sh --logs      # tail logs
#
# Prerequisites:
#   - Docker Engine >= 20.10
#   - Docker Compose V2 (docker compose, not docker-compose)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log()   { echo -e "${GREEN}[DEPLOY]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── Checks ────────────────────────────────────────────────────────────────────

check_prerequisites() {
    if ! command -v docker &>/dev/null; then
        err "Docker is not installed. Install Docker Engine: https://docs.docker.com/engine/install/"
        exit 1
    fi

    if ! docker compose version &>/dev/null; then
        err "Docker Compose V2 not found. Install: https://docs.docker.com/compose/install/"
        exit 1
    fi

    local docker_version
    docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
    log "Docker version: ${docker_version}"
}

# ── Commands ──────────────────────────────────────────────────────────────────

do_stop() {
    cd "$PROJECT_DIR"
    log "Stopping Horus..."
    docker compose down
    log "Stopped."
}

do_status() {
    cd "$PROJECT_DIR"
    docker compose ps
    echo "──"
    docker compose logs --tail=20 horus 2>/dev/null || true
}

do_logs() {
    cd "$PROJECT_DIR"
    docker compose logs -f horus
}

# Snapshot the SQLite DB before an update so a bad deploy never loses data.
# Non-fatal: if the container isn't running or has no DB yet, warn and continue.
do_backup() {
    cd "$PROJECT_DIR"
    local backup_dir="$PROJECT_DIR/backups"
    mkdir -p "$backup_dir"
    local stamp
    stamp="$(date +%Y%m%d-%H%M%S)"
    local dest="$backup_dir/horus.db.${stamp}.bak"

    log "Backing up database → backups/horus.db.${stamp}.bak"
    if docker compose cp horus:/app/state/horus.db "$dest" 2>/dev/null; then
        log "Backup saved ($(du -h "$dest" | cut -f1))"
        # Retain the 10 most recent backups; prune older ones.
        ls -1t "$backup_dir"/horus.db.*.bak 2>/dev/null | tail -n +11 | xargs -r rm -f
    else
        rm -f "$dest"
        warn "Could not back up DB (container not running or no DB yet) — continuing."
    fi
}

do_update() {
    cd "$PROJECT_DIR"
    do_backup
    log "Rebuilding Horus..."
    docker compose build --no-cache horus
    docker compose up -d
    log "Rebuilt and restarted."
    do_healthcheck
}

do_deploy() {
    cd "$PROJECT_DIR"

    # Check .env exists
    if [[ ! -f .env ]]; then
        if [[ -f .env.sample ]]; then
            warn ".env not found. Copying .env.sample → .env"
            warn "Edit .env to configure your data sources!"
            cp .env.sample .env
        else
            err "No .env or .env.sample found. Create a .env file first."
            exit 1
        fi
    fi

    log "Building Horus..."
    docker compose build horus

    log "Starting Horus..."
    docker compose up -d

    do_healthcheck

    log ""
    log "═══════════════════════════════════════════════════════════════"
    log "  Horus deployed successfully!"
    log ""
    local _host_port="${HORUS_HOST_PORT:-${HORUS_WEB_PORT:-8080}}"
    log "  Web UI:    http://localhost:${_host_port}"
    log "  Health:    http://localhost:${_host_port}/api/health"
    log ""
    log "  Commands:"
    log "    ./scripts/deploy.sh --status     # check status"
    log "    ./scripts/deploy.sh --logs       # view logs"
    log "    ./scripts/deploy.sh --update     # rebuild + restart"
    log "    ./scripts/deploy.sh --stop       # stop"
    log "═══════════════════════════════════════════════════════════════"
}

do_healthcheck() {
    # HORUS_HOST_PORT overrides the host-mapped port (docker-compose maps
    # 8081:8080 by default); falls back to HORUS_WEB_PORT then 8080.
    local port="${HORUS_HOST_PORT:-${HORUS_WEB_PORT:-8080}}"
    local url="http://localhost:${port}/api/health"
    local max_attempts=15
    local attempt=0

    log "Waiting for Horus to be ready (${url})..."

    while [[ $attempt -lt $max_attempts ]]; do
        if curl -sf "$url" &>/dev/null; then
            local status
            status=$(curl -sf "$url" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null || echo "unknown")
            if [[ "$status" == "ok" ]]; then
                log "Horus is healthy ✓"
                return 0
            else
                warn "Horus is responding but status=${status}"
            fi
        fi
        attempt=$((attempt + 1))
        sleep 2
    done

    err "Horus did not become healthy after $((max_attempts * 2))s"
    err "Check logs: ./scripts/deploy.sh --logs"
    return 1
}

# ── Main ──────────────────────────────────────────────────────────────────────

check_prerequisites

case "${1:-}" in
    --stop)
        do_stop
        ;;
    --status)
        do_status
        ;;
    --logs)
        do_logs
        ;;
    --update)
        do_update
        ;;
    --help|-h)
        echo "Usage: $0 [--stop|--status|--logs|--update]"
        echo ""
        echo "  (none)     Full deploy (build + start)"
        echo "  --update   Rebuild and restart"
        echo "  --stop     Stop and remove containers"
        echo "  --status   Show container status + recent logs"
        echo "  --logs     Tail logs"
        ;;
    *)
        do_deploy
        ;;
esac
