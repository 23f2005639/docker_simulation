#!/bin/bash
set -euo pipefail

echo "[ESCAPE] CVE-2024-21626 Simulation — runc /proc/self/fd WORKDIR escape"
echo "[ESCAPE] Listing /proc/self/fd to trigger syscall detection..."
ls -la /proc/self/fd/

echo "[ESCAPE] Traversing into /proc/self/fd (Falco: proc.cwd startswith /proc/self/fd)..."
cd /proc/self/fd/ && pwd

echo "[ESCAPE] Enumerating fd symlinks for host filesystem references..."
for fd in /proc/self/fd/*; do
    target=$(readlink "$fd" 2>/dev/null || true)
    if [[ "$target" == "/"* ]] && [[ "$target" != "/proc"* ]] && [[ "$target" != "/dev"* ]]; then
        echo "[ESCAPE][!] Host fd symlink: $fd -> $target"
    fi
done

echo "[ESCAPE] Attack simulation complete — check Falco + AI gateway output"
