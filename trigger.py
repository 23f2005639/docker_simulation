#!/usr/bin/env python3
"""
trigger.py — Manual attack trigger for Docker Security Simulation Lab

Usage:
    python trigger.py --attack escape    # CVE-2024-21626 container escape
    python trigger.py --attack sock      # Docker socket abuse
    python trigger.py --attack lateral   # Lateral movement via nsenter
    python trigger.py --attack secrets   # Sensitive file access
    python trigger.py --attack authz     # CVE-2026-34040 AuthZ bypass
    python trigger.py --attack all       # Fire all with 10s gaps
    python trigger.py --health           # Check all attackers are ready
"""
import argparse
import sys
import time

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

ATTACKERS: dict[str, str] = {
    "escape":  "http://localhost:5001",
    "sock":    "http://localhost:5002",
    "lateral": "http://localhost:5003",
    "secrets": "http://localhost:5004",
    "authz":   "http://localhost:5005",
}

DESCRIPTIONS: dict[str, str] = {
    "escape":  "CVE-2024-21626 — runc /proc/self/fd container escape",
    "sock":    "Docker socket abuse — privileged sibling container spawn",
    "lateral": "Lateral movement — nsenter + east-west network traversal",
    "secrets": "Sensitive file access — /etc/shadow + env credential dump",
    "authz":   "CVE-2026-34040 — AuthZ plugin bypass via oversized body",
}

COLORS = {
    "escape":  "\033[91m",
    "sock":    "\033[93m",
    "lateral": "\033[94m",
    "secrets": "\033[95m",
    "authz":   "\033[96m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def _c(name: str, text: str) -> str:
    return f"{COLORS.get(name, '')}{text}{RESET}"


def check_health(name: str) -> bool:
    try:
        resp = requests.get(f"{ATTACKERS[name]}/health", timeout=3)
        data = resp.json()
        status = data.get("status", "unknown")
        icon = "✓" if status == "ready" else "?"
        print(_c(name, f"  [{icon}] {name:<10} {status} — {data.get('scenario', '')}"))
        return resp.status_code == 200 and status == "ready"
    except requests.RequestException as e:
        print(_c(name, f"  [✗] {name:<10} UNREACHABLE — {e}"))
        return False


def trigger(name: str) -> bool:
    print(_c(name, f"\n{BOLD}[►] Triggering: {name}{RESET}"))
    print(_c(name, f"    {DESCRIPTIONS[name]}"))
    print(_c(name, f"    → POST {ATTACKERS[name]}/trigger"))
    try:
        resp = requests.post(f"{ATTACKERS[name]}/trigger", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        print(_c(name, f"    ✓ {data}"))
        print(_c(name, f"    Watch: docker logs -f ai-gateway"))
        return True
    except requests.RequestException as e:
        print(_c(name, f"    ✗ Failed: {e}"))
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Docker Security Simulation Lab — Attack Trigger",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--attack",
        choices=[*ATTACKERS, "all"],
        help="Which attack to trigger",
    )
    group.add_argument(
        "--health",
        action="store_true",
        help="Check all attackers are healthy and ready",
    )
    args = parser.parse_args()

    if args.health:
        print(f"\n{BOLD}Attacker Health Check{RESET}")
        print("─" * 50)
        all_ok = all(check_health(name) for name in ATTACKERS)
        print("─" * 50)
        print(f"Status: {'all ready ✓' if all_ok else 'some unreachable ✗'}\n")
        sys.exit(0 if all_ok else 1)

    if args.attack == "all":
        names = list(ATTACKERS)
        for i, name in enumerate(names):
            trigger(name)
            if i < len(names) - 1:
                print(f"\n  [*] Waiting 10s before next attack...")
                time.sleep(10)
    else:
        trigger(args.attack)


if __name__ == "__main__":
    main()
