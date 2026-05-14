# Multi-Attacker Docker Security Simulation — Design Spec
Date: 2026-05-11

## Overview

A Docker Compose environment with 5 specialized attacker containers, each dedicated to one attack type, targeting isolated misconfigured victim containers. Falco monitors all syscalls and fires webhooks to a dual-LLM AI gateway (quick triage + deep analysis). Each attacker is triggered manually via CLI for live walkthrough control.

---

## 1. Attack Scenarios

| # | Attacker Container | Attack Type | CVE / Technique | Victim Misconfiguration |
|---|-------------------|-------------|-----------------|------------------------|
| 1 | `attacker-escape` | Container escape | CVE-2024-21626 (runc /proc/self/fd WORKDIR) | Unpatched runc, WORKDIR set to /proc/self/fd/N |
| 2 | `attacker-sock` | Docker socket abuse | docker.sock mount → sibling container hijack | /var/run/docker.sock mounted read-write |
| 3 | `attacker-lateral` | Lateral movement | nsenter + east-west network traversal | No NetworkPolicy, shared bridge network |
| 4 | `attacker-secrets` | Sensitive file access | /etc/shadow + mounted K8s secrets + env dump | hostPath mounts, secrets in env vars |
| 5 | `attacker-authz` | AuthZ plugin bypass | CVE-2026-34040 (>1MB body drops AuthZ check) | Docker Engine with AuthZ plugin, unpatched |

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Docker Compose Host                           │
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐                          │
│  │ attacker-    │────▶│ victim-      │  (escape-net)            │
│  │ escape       │     │ escape       │                          │
│  └──────────────┘     └──────────────┘                          │
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐                          │
│  │ attacker-    │────▶│ victim-sock  │  (sock-net)              │
│  │ sock         │     │              │                          │
│  └──────────────┘     └──────────────┘                          │
│                                                                  │
│  ┌──────────────┐     ┌───────┐ ┌───────┐                       │
│  │ attacker-    │────▶│victim │ │victim │  (lateral-net)        │
│  │ lateral      │     │-lat-a │ │-lat-b │                       │
│  └──────────────┘     └───────┘ └───────┘                       │
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐                          │
│  │ attacker-    │────▶│ victim-      │  (secrets-net)           │
│  │ secrets      │     │ secrets      │                          │
│  └──────────────┘     └──────────────┘                          │
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐ ┌──────────────┐         │
│  │ attacker-    │────▶│ victim-authz │ │ authz-plugin │  (authz-net) │
│  │ authz        │     │              │ │              │         │
│  └──────────────┘     └──────────────┘ └──────────────┘         │
│                                                                  │
│  ┌──────────────────────────────────────────────────────┐        │
│  │  falco  (bridges all networks, host pid/net/proc)    │        │
│  └────────────────────────┬─────────────────────────────┘        │
│                           │ webhook HTTP POST                    │
│  ┌────────────────────────▼─────────────────────────────┐        │
│  │  ai-gateway  (FastAPI)                               │        │
│  │  ├── GPT-5.4-nano  → instant triage (<1s)            │        │
│  │  └── GPT-5.5       → full report (async)             │        │
│  └──────────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────┘

trigger.py --attack [escape|sock|lateral|secrets|authz]
  └── HTTP POST /trigger on attacker container
```

---

## 3. Directory Structure

```
docker_simulation/
├── docker-compose.yml
├── trigger.py                    # CLI: trigger.py --attack escape
├── .env.example                  # OPENAI_API_KEY, etc.
│
├── falco/
│   ├── falco.yaml                # Webhook output config
│   └── rules/
│       ├── escape_rules.yaml
│       ├── sock_rules.yaml
│       ├── lateral_rules.yaml
│       ├── secrets_rules.yaml
│       └── authz_rules.yaml
│
├── ai-gateway/
│   ├── Dockerfile
│   ├── main.py                   # FastAPI webhook receiver
│   ├── analyzer.py               # LiteLLM dual-model calls
│   ├── prompts.py                # Triage + deep analysis prompts
│   └── requirements.txt
│
├── attackers/
│   ├── escape/
│   │   ├── Dockerfile
│   │   ├── server.py             # Flask /trigger endpoint
│   │   └── attack.sh             # runc fd leak exploit sim
│   ├── sock/
│   │   ├── Dockerfile
│   │   ├── server.py
│   │   └── attack.py             # Docker API via socket
│   ├── lateral/
│   │   ├── Dockerfile
│   │   ├── server.py
│   │   └── attack.sh             # nsenter + nmap sweep
│   ├── secrets/
│   │   ├── Dockerfile
│   │   ├── server.py
│   │   └── attack.sh             # read shadow/secrets/env
│   └── authz/
│       ├── Dockerfile
│       ├── server.py
│       └── attack.py             # CVE-2026-34040 oversized body
│
└── victims/
    ├── escape/Dockerfile         # vulnerable runc WORKDIR config
    ├── sock/Dockerfile           # docker.sock mounted
    ├── lateral-a/Dockerfile      # open east-west, no policy
    ├── lateral-b/Dockerfile      # open east-west, no policy
    ├── secrets/Dockerfile        # hostPath + secrets in env
    └── authz/Dockerfile          # AuthZ plugin + Docker daemon config
```

---

## 4. Trigger Mechanism

Each attacker container runs a minimal Flask server at port 5000:
- `GET /health` — readiness check
- `POST /trigger` — starts the attack script, returns `{"status": "attacking"}`

CLI usage:
```bash
python trigger.py --attack escape    # fires attacker-escape
python trigger.py --attack sock      # fires attacker-sock
python trigger.py --attack lateral
python trigger.py --attack secrets
python trigger.py --attack authz
python trigger.py --attack all       # fires all with 10s gaps
```

---

## 5. Falco Integration

- Falco runs as a privileged container with host mounts: `/proc`, `/dev`, `/boot`, `/lib/modules`, `/usr`, `/var/run/docker.sock`
- Output: HTTP webhook to `http://ai-gateway:8000/falco-alert`
- Custom rules per scenario in `/etc/falco/rules.d/`
- Alert payload includes: container name, image, user, command, syscall, file path, network dest

### Key Rules Per Scenario
| Scenario | Falco Rule Trigger |
|----------|-------------------|
| escape | `proc.cwd startswith /proc/self/fd` |
| sock | Docker socket write + new container creation syscall |
| lateral | `nsenter` process spawn + cross-namespace net connection |
| secrets | `open_read` on `/etc/shadow`, `/var/run/secrets`, `/proc/*/environ` |
| authz | Oversized POST to Docker daemon socket (body > 512KB) |

---

## 6. AI Gateway (LiteLLM Dual-Model)

### Stack
- FastAPI + uvicorn
- `litellm` for unified model calls
- `asyncio.gather` for parallel model invocation

### Per-Alert Flow
```
Falco webhook → POST /falco-alert
  → tag alert with scenario name (from container label)
  → asyncio.gather(
       gpt-5.4-nano: one-line triage (severity, what happened),
       gpt-5.5:      full report (MITRE ATT&CK ID, misconfiguration
                     that enabled it, predicted next move,
                     risk score 0-10, hardened config diff)
    )
  → print structured JSON to stdout (color-coded by severity)
```

### Model Config
```python
# analyzer.py
TRIAGE_MODEL = "openai/gpt-5.4-nano"   # fast, cheap, instant
ANALYSIS_MODEL = "openai/gpt-5.5"       # deep, thorough
```

---

## 7. Network Isolation

| Network | Containers | Purpose |
|---------|-----------|---------|
| `escape-net` | attacker-escape, victim-escape | isolated escape sim |
| `sock-net` | attacker-sock, victim-sock | sock abuse |
| `lateral-net` | attacker-lateral, victim-lat-a, victim-lat-b | east-west movement |
| `secrets-net` | attacker-secrets, victim-secrets | secret exfil |
| `authz-net` | attacker-authz, victim-authz, authz-plugin | CVE-2026-34040 |
| `monitoring` | falco, ai-gateway | alert pipeline |

Falco joins all networks. AI gateway joins only `monitoring`.

---

## 8. Environment Variables

```env
OPENAI_API_KEY=sk-...
LITELLM_LOG=DEBUG          # optional: verbose LiteLLM logging
AI_GATEWAY_PORT=8000
FALCO_WEBHOOK_URL=http://ai-gateway:8000/falco-alert
```

---

## 9. Out of Scope

- Kubernetes orchestration (Docker Compose only)
- Pre-execution supply chain attack simulation
- Persistent storage for alert history (stdout only)
- Authentication on trigger endpoints (local lab use only)
