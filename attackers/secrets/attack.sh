#!/bin/bash

echo "[SECRETS] Sensitive File Access Simulation"

echo "[SECRETS] Attempting to read /etc/shadow..."
if cat /etc/shadow 2>/dev/null; then
    echo "[SECRETS][!] /etc/shadow read successful — password hashes exposed"
else
    echo "[SECRETS][-] /etc/shadow not readable directly"
fi

echo "[SECRETS] Scanning for mounted Kubernetes secrets..."
for dir in /var/run/secrets /run/secrets /mnt/secrets /secrets; do
    if [ -d "$dir" ]; then
        echo "[SECRETS][!] Secret directory found: $dir"
        find "$dir" -type f 2>/dev/null | while read -r f; do
            echo "[SECRETS][!] Secret file: $f"
            head -c 100 "$f" 2>/dev/null
            echo ""
        done
    fi
done

echo "[SECRETS] Dumping environment variables for credential patterns..."
cat /proc/1/environ 2>/dev/null | tr '\0' '\n' \
    | grep -iE "(key|secret|password|token|api|jwt|db_|database)" \
    | head -20 \
    | while read -r line; do
        echo "[SECRETS][!] Credential env var: $line"
    done

env | grep -iE "(key|secret|password|token|api|jwt|db_|database)" | head -10 \
    | while read -r line; do
        echo "[SECRETS][!] Own env credential: $line"
    done

echo "[SECRETS] Attack simulation complete"
