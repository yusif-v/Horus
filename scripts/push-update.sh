#!/usr/bin/env bash
# ─── Horus Push-Update ───────────────────────────────────────────────────────
# Syncs the Horus source to the server and triggers a rebuild + restart.
# Run this from your dev machine when you want to push an update.
#
# Usage:
#   ./scripts/push-update.sh [user@host]
#
# What it does:
#   1. rsync source code to the server (fast, incremental)
#   2. SSH in and rebuild the Docker image on the server (native arch)
#   3. Restart via docker compose + health check
#
# Defaults:
#   SERVER=cti@172.22.1.4
#   REMOTE_DIR=~/horus-app

set -euo pipefail

SERVER="${1:-cti@172.22.1.4}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[push-update]${NC} $*"; }
warn() { echo -e "${YELLOW}[push-update]${NC} $*"; }
err()  { echo -e "${RED}[push-update]${NC} $*" >&2; exit 1; }

# ── Preflight ─────────────────────────────────────────────────────────────────

ssh -o BatchMode=yes -o ConnectTimeout=10 "$SERVER" "echo ok" &>/dev/null || \
    err "Cannot reach $SERVER. Is the VPN up?"

log "Connected to $SERVER"

# ── Sync source code ──────────────────────────────────────────────────────────

log "Syncing source code..."
rsync -az --delete \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.mypy_cache' \
    --exclude='horus.egg-info' \
    --exclude='graphify-out' \
    --exclude='reports' \
    --exclude='state' \
    --exclude='backups' \
    --exclude='.env' \
    --exclude='99 Meta' \
    --exclude='.claude' \
    --exclude='.playwright-mcp' \
    -e "ssh -o StrictHostKeyChecking=no" \
    "$PROJECT_DIR/" \
    "$SERVER:~/horus-app/"

log "Source synced."

# ── Build and restart on server ───────────────────────────────────────────────

log "Building and restarting on server..."
ssh -o StrictHostKeyChecking=no "$SERVER" bash <<'REMOTE'
set -euo pipefail
INSTALL_DIR="$HOME/horus-app"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[server]${NC} $*"; }
warn() { echo -e "${YELLOW}[server]${NC} $*"; }

cd "$INSTALL_DIR"

# Backup DB before update
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^horus$'; then
    BACKUP_DIR="$INSTALL_DIR/backups"
    mkdir -p "$BACKUP_DIR"
    STAMP=$(date +%Y%m%d-%H%M%S)
    DEST="$BACKUP_DIR/horus.db.${STAMP}.bak"
    if docker cp horus:/app/state/horus.db "$DEST" 2>/dev/null; then
        log "DB backed up → backups/horus.db.${STAMP}.bak ($(du -h "$DEST" | cut -f1))"
        ls -1t "$BACKUP_DIR"/horus.db.*.bak 2>/dev/null | tail -n +11 | xargs -r rm -f
    else
        warn "No DB to back up yet."
    fi
fi

# Rebuild native image (no cache for source changes)
log "Rebuilding Docker image..."
docker build -t horus:latest .
docker tag horus:latest horus-app-horus:latest

# Restart
log "Restarting..."
docker compose down 2>/dev/null || true
docker compose up -d

# Health check
log "Waiting for Horus to be healthy..."
PORT=$(grep -E '^HORUS_HOST_PORT=' .env 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "8081")
PORT="${PORT:-8081}"
URL="http://localhost:${PORT}/api/health"
for i in $(seq 1 15); do
    if curl -sf "$URL" | python3 -c "import sys,json; exit(0 if json.load(sys.stdin)['status']=='ok' else 1)" 2>/dev/null; then
        log "Horus is healthy ✓"
        break
    fi
    sleep 2
done
REMOTE

# ── Summary ───────────────────────────────────────────────────────────────────

SERVER_IP=$(ssh -o StrictHostKeyChecking=no "$SERVER" "hostname -I | awk '{print \$1}'" 2>/dev/null || echo "server")
log ""
log "═══════════════════════════════════════════════════════════"
log "  Horus updated on $SERVER"
log ""
log "  Web UI:  http://${SERVER_IP}:8081"
log "  Health:  http://${SERVER_IP}:8081/api/health"
log "═══════════════════════════════════════════════════════════"
