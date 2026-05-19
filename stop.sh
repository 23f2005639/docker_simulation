#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colours ────────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${BOLD}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }

echo -e "${BOLD}Docker Security Simulation Lab — Stop${NC}"
echo "────────────────────────────────────────────────────"

# ── Optional: remove images too ───────────────────────────────────────────────
REMOVE_IMAGES=false
if [[ "${1:-}" == "--clean" ]]; then
    REMOVE_IMAGES=true
fi

if [[ "$REMOVE_IMAGES" == "true" ]]; then
    info "Stopping containers and removing images..."
    docker compose down --rmi local
else
    info "Stopping and removing containers..."
    docker compose down
fi

success "All containers stopped."

if [[ "$REMOVE_IMAGES" == "true" ]]; then
    success "Local images removed. Next start will rebuild from scratch."
    echo ""
    echo "  To start again: ./start.sh"
else
    echo ""
    echo "  Images are kept for a faster next start."
    echo "  To also remove images: ./stop.sh --clean"
    echo "  To start again:        ./start.sh"
fi
echo ""
