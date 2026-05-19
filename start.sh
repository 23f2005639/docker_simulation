#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${BOLD}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; }

echo -e "${BOLD}Docker Security Simulation Lab — Start${NC}"
echo "────────────────────────────────────────────────────"

# ── Prereq checks ──────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    error "Docker not found. Install Docker Desktop or Docker Engine first."
    exit 1
fi

if ! docker info &>/dev/null; then
    error "Docker daemon is not running. Start Docker Desktop and try again."
    exit 1
fi

if [[ ! -f ".env" ]]; then
    error ".env file not found."
    echo "  Create it with:"
    echo "    echo 'OPENAI_API_KEY=sk-your-key-here' > .env"
    exit 1
fi

if ! grep -q "OPENAI_API_KEY" .env; then
    error ".env exists but OPENAI_API_KEY is missing."
    exit 1
fi

# ── Build & start ──────────────────────────────────────────────────────────────
info "Building and starting all containers..."
docker compose up --build -d

# ── Wait for ai-gateway ────────────────────────────────────────────────────────
info "Waiting for ai-gateway to become healthy..."
ATTEMPTS=0
MAX=30
until curl -sf http://localhost:8000/health >/dev/null 2>&1; do
    ATTEMPTS=$((ATTEMPTS + 1))
    if [[ $ATTEMPTS -ge $MAX ]]; then
        error "ai-gateway did not become healthy after ${MAX} seconds."
        echo "  Check logs: docker logs ai-gateway"
        exit 1
    fi
    sleep 1
done
success "ai-gateway is healthy"

# ── Wait for Falco ─────────────────────────────────────────────────────────────
info "Waiting for Falco to load its eBPF probe (up to 90s)..."
ATTEMPTS=0
MAX=90
until docker logs falco 2>&1 | grep -q "Opening 'syscall' source with modern BPF probe"; do
    ATTEMPTS=$((ATTEMPTS + 1))
    if [[ $ATTEMPTS -ge $MAX ]]; then
        warn "Falco didn't finish loading within ${MAX}s — it may still be downloading the probe."
        warn "Check with: docker logs falco --tail 20"
        break
    fi
    sleep 1
done
if [[ $ATTEMPTS -lt $MAX ]]; then
    success "Falco is live and monitoring syscalls"
fi

# ── Attacker health check ──────────────────────────────────────────────────────
info "Checking attacker containers..."
ALL_OK=true
declare -A ATTACKERS=( [escape]=5001 [sock]=5002 [lateral]=5003 [secrets]=5004 [authz]=5005 )
for name in "${!ATTACKERS[@]}"; do
    port="${ATTACKERS[$name]}"
    if curl -sf "http://localhost:${port}/health" >/dev/null 2>&1; then
        success "  attacker-${name} ready"
    else
        warn "  attacker-${name} not yet responding on port ${port}"
        ALL_OK=false
    fi
done

if [[ "$ALL_OK" == "false" ]]; then
    warn "Some attackers are still starting. Run 'python3 trigger.py --health' in a few seconds."
fi

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}Lab is running.${NC}"
echo ""
echo "  Dashboard:  http://localhost:8000/dashboard"
echo "  Trigger:    python3 trigger.py --attack <escape|sock|lateral|secrets|authz|all>"
echo "  Health:     python3 trigger.py --health"
echo "  Stop:       ./stop.sh"
echo ""
