# Windows setup guide

This guide covers getting the Docker Security Simulation Lab running on Windows with Docker Desktop. Everything runs inside the WSL 2 Linux VM that Docker Desktop manages, so Falco's eBPF probe works the same as it would on a native Linux machine.

---

## Does Falco actually work on Windows?

Yes. Docker Desktop uses WSL 2 as its backend, which is a real Linux kernel (5.15+) running in a Hyper-V VM. Falco targets that kernel with its `modern_ebpf` driver — it attaches eBPF programs to kernel tracepoints and monitors syscalls from every container Docker runs. The fact that Windows sits underneath doesn't matter because Falco never sees Windows processes, only what's inside the WSL 2 VM.

The one thing to be aware of: on first run, Falco downloads its eBPF CO-RE object from the Falco CDN. That takes 30–60 seconds depending on your internet speed, and Docker Desktop needs to be running with WSL Integration enabled or the mounts Falco needs won't exist.

---

## Prerequisites

### Docker Desktop

Download Docker Desktop for Windows from docker.com. During installation, select WSL 2 as the backend when prompted (it's the default option on Windows 10/11 with Hyper-V). After it installs, open Docker Desktop and wait until the whale icon in the system tray stops animating — that means the engine is ready.

After installation, go to:

**Settings → Resources → WSL Integration**

Enable integration for your default WSL 2 distro (usually `Ubuntu`). Click **Apply & Restart**. Without this step, the `/sys/fs/bpf` and `/sys/kernel/debug` mounts that Falco needs won't be present inside Docker's Linux environment.

### An OpenAI API key

The AI analysis layer calls GPT-4o via the OpenAI API. You need a key with available credits.

1. Go to platform.openai.com and create an account if you don't have one
2. Go to API Keys and generate a new secret key
3. Copy it — you'll only see it once

---

## Setup

### Step 1 — Get the project files

Copy the `docker_simulation` folder to your Windows machine. USB drive, zip file, `git clone` — any method works. If you use `git clone`, run it from Windows Terminal rather than Git Bash to avoid line-ending issues.

### Step 2 — Create the `.env` file

Inside the `docker_simulation` folder, create a file named `.env` (no extension — just `.env`). Open Notepad or VS Code and write:

```
OPENAI_API_KEY=sk-your-actual-key-here
```

Replace the placeholder with your real key. Save the file.

If Windows Explorer is hiding file extensions, you can create the file from PowerShell:

```powershell
cd C:\path\to\docker_simulation
"OPENAI_API_KEY=sk-your-key-here" | Out-File -FilePath .env -Encoding utf8 -NoNewline
```

The `.env` file is excluded from git via `.gitignore`. Don't commit it.

### Step 3 — Install Python dependencies

The root `requirements.txt` covers `trigger.py` and all other Python code in the project:

```powershell
cd C:\path\to\docker_simulation
pip install -r requirements.txt
```

This installs:

| Package | Used by |
|---|---|
| `requests` | `trigger.py` — fires attacks over HTTP |
| `fastapi`, `uvicorn`, `litellm`, `httpx`, `sse-starlette` | ai-gateway (also built into the Docker image) |
| `flask` | all 5 attacker containers (also built into Docker images) |
| `requests-unixsocket2` | attacker-sock — Python HTTP over Unix socket |

The Docker images install their own scoped dependencies at build time. This step is only needed if you want to run `trigger.py` or any Python file directly on your Windows machine outside Docker.

### Step 5 — Start the lab

Open PowerShell or Windows Terminal, navigate to the `docker_simulation` folder, and run:

```powershell
cd C:\path\to\docker_simulation
docker compose up --build -d
```

The first run downloads all base images and builds the attacker/victim/gateway containers. Expect 3–7 minutes depending on your internet connection. You'll see a stream of pull and build output — that's normal.

### Step 6 — Wait for Falco

After `docker compose up` finishes, Falco still needs a moment to download and load its eBPF probe. Wait about 60 seconds, then check:

```powershell
docker logs falco --tail 20
```

Look for a line like:

```
Starting gRPC server...
```

That's Falco telling you it's live and monitoring syscalls. If you don't see it after 90 seconds, see the troubleshooting section below.

### Step 7 — Open the dashboard

Open your browser and go to:

```
http://localhost:8000/dashboard
```

You should see the Docker Security Simulation Lab dashboard. The top-right corner shows the SSE connection status — it turns green once the gateway's event stream connects (usually within 2 seconds of the page loading).

---

## Using the lab

The screen is split into a 2×2 grid showing four panels at once: AI Analysis, Attack Simulation, Falco Logs, and Attack History. Above the grid is a horizontal strip with all 5 attack scenarios.

**To run an attack:** click the Trigger button next to any scenario name. The attack executes immediately in that container.

**What each scenario does:**

| Scenario | Technique | What actually runs |
|---|---|---|
| Container Escape | CVE-2024-21626 (T1611) | `cd /proc/self/fd/` — triggers Falco's proc.cwd rule |
| Docker Socket Abuse | T1610 | Python hits docker.sock API, spawns a privileged container |
| Lateral Movement | T1046 + T1609 | nmap subnet scan, then nsenter into PID 1's namespaces |
| Secrets Exfiltration | T1552 | reads `/etc/shadow` and `/proc/1/environ` for credential patterns |
| AuthZ Bypass | CVE-2026-34040 | sends a 1.1MB POST to docker.sock to evade AuthZ inspection |

**Reading an alert:** Within 5–15 seconds of triggering, an alert card appears in the AI Analysis panel. Each card shows:

- A severity badge (CRITICAL / WARNING / NOTICE)
- The Falco rule name that fired
- A one-sentence triage summary from GPT-4o
- An expandable View Analysis section with MITRE technique, risk score, the misconfiguration that enabled the attack, what the attacker is likely to do next, and a corrected Docker Compose snippet

**The simulation panel:** As alerts arrive, the SVG container topology animates — the attacker node pulses red, a packet path draws itself toward the central Falco node, then the victim node glows green and a DETECTED badge appears. The MITRE ATT&CK tactic boxes on the right light up and collect technique chips as each scenario fires.

**Each panel has a fullscreen button** (the double-arrow icon in the panel header). Click it to expand that panel to fill the whole screen; click again to return to the grid.

**Clearing the state:** The Clear button in the top bar resets all panels, removes all alert cards, and resets the simulation topology.

---

## Health indicators

The dot indicators in the scenarios strip show whether each attacker container is reachable. Green means the container's `/health` endpoint responded. Red means it's unreachable — usually because the container is still starting or has crashed.

If a container shows red after 60 seconds, check its logs:

```powershell
docker logs attacker-escape
docker logs attacker-sock
```

---

## Stopping the lab

```powershell
docker compose down
```

This stops and removes all 13 containers and their networks. Your files and `.env` are not touched.

To remove the downloaded images too (frees several GB):

```powershell
docker compose down --rmi all
```

---

## CLI alternative

If you prefer the command line over the browser:

```powershell
# install dependencies first if you haven't already (Step 3)
pip install -r requirements.txt

# check all attacker containers are responding
python trigger.py --health

# trigger a single attack
python trigger.py --attack escape
python trigger.py --attack sock
python trigger.py --attack lateral
python trigger.py --attack secrets
python trigger.py --attack authz

# trigger all five with 10-second gaps between each
python trigger.py --attack all
```

The AI analysis prints to the ai-gateway container log:

```powershell
docker logs ai-gateway -f
```

---

## Troubleshooting

### "Reconnecting..." shows in the top-right corner

The ai-gateway is still starting. Reload the page after 30 seconds. If it persists, check:

```powershell
docker logs ai-gateway --tail 20
```

### Falco logs show BPF errors or fail to start

The most common cause on Windows is missing WSL Integration. Open Docker Desktop → Settings → Resources → WSL Integration, enable your default distro, and click Apply & Restart. Then restart the stack:

```powershell
docker compose down
docker compose up -d
```

If you see `scap_init failed` in Falco logs even after that, the WSL 2 kernel version may be too old. Update it by running in PowerShell (as Administrator):

```powershell
wsl --update
```

### No alerts appear after triggering

Check the gateway received the Falco alert:

```powershell
docker logs ai-gateway --tail 30
```

If you see `[ANALYSIS ERROR]`, the OpenAI key in `.env` is incorrect or the account is out of credits. Fix the key and restart just the gateway:

```powershell
docker compose up -d ai-gateway
```

If there's no mention of the alert at all, Falco may not be forwarding. Check:

```powershell
docker logs falco --tail 30
```

### Attack trigger returns an error in the dashboard

The attacker container is likely still starting. Run:

```powershell
docker ps
```

All containers should show `Up`. If any show `Restarting`, check their logs with `docker logs <container-name>`.

### Dashboard shows stale content after you edit a file

The ai-gateway image bakes the dashboard HTML at build time. After any change to `dashboard.html`, rebuild and restart:

```powershell
docker compose up --build -d ai-gateway
```

### Port 8000 is already in use

Something else on your machine is using port 8000. Either stop that process or change the gateway port in `docker-compose.yml`:

```yaml
ports:
  - "9000:8000"  # change 8000 to any free port
```

Then access the dashboard at `http://localhost:9000/dashboard`.
