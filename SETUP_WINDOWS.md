# Windows Setup Guide — Docker Security Simulation Lab

## Prerequisites

### 1. Install Docker Desktop
- Download Docker Desktop for Windows from the official Docker website
- During installation, choose **WSL 2** as the backend (recommended)
- After install, open Docker Desktop and wait until the status bar shows "Docker Desktop is running"

### 2. Enable WSL 2 Integration (if not already done)
- Open Docker Desktop → Settings → Resources → WSL Integration
- Enable integration for your default WSL 2 distro
- Click **Apply & Restart**

### 3. Get an OpenAI API Key
- Create an account at platform.openai.com
- Generate an API key under API Keys
- Keep it handy — you'll paste it in the next step

---

## Setup

### Step 1 — Get the project
Copy the `docker_simulation` folder to your Windows machine (e.g. via USB drive, zip file, or git clone).

### Step 2 — Create the `.env` file
Inside the `docker_simulation` folder, create a file called `.env` (no extension) with this content:

```
OPENAI_API_KEY=sk-your-key-here
```

Replace `sk-your-key-here` with your actual OpenAI API key.

> **Important:** Never share or commit this file. It is excluded from git by `.gitignore`.

### Step 3 — Start the lab
Open **PowerShell** (or Windows Terminal) and navigate to the project folder:

```powershell
cd C:\path\to\docker_simulation
docker compose up --build -d
```

This downloads all images and builds the containers. The first run takes 2–5 minutes.

### Step 4 — Wait for Falco to be ready
Falco downloads its eBPF probe on first run. Wait about 60 seconds after `docker compose up` completes, then check:

```powershell
docker logs falco --tail 20
```

You should see a line like:

```
Starting gRPC server...
```

That means Falco is live and sending alerts.

### Step 5 — Open the dashboard
Open your browser and go to:

```
http://localhost:8000/dashboard
```

You should see the **Docker Security Simulation Lab** dashboard with a green "Connected" indicator in the top-right corner.

---

## Using the Dashboard

### Trigger an attack
Click the **Trigger** button next to any scenario in the left sidebar.

| Scenario | What it simulates |
|---|---|
| Container Escape | CVE-2024-21626 — runc /proc/self/fd directory traversal |
| Docker Socket Abuse | Mount docker.sock to spawn privileged containers |
| Lateral Movement | nsenter + east-west network scanning |
| Secrets Exfiltration | Read /etc/shadow and process environment variables |
| AuthZ Bypass | CVE-2026-34040 — oversized body bypasses AuthZ plugin |

### Read the AI analysis
Within 5–15 seconds of triggering an attack, an alert card appears in the **Live Alert Feed** on the right. Each card shows:

- **Severity badge** (CRITICAL / HIGH / MEDIUM / LOW)
- **Rule name** and scenario
- **Triage** — one-line AI summary
- Click **View AI Analysis** to expand:
  - MITRE ATT&CK technique
  - What happened (plain English)
  - The misconfiguration that enabled the attack
  - Risk score (0–10) with a visual bar
  - What the attacker is likely to do next
  - Hardened Docker Compose config to fix the issue

### System Health panel
The **System Health** section shows whether each attacker container is ready (green) or unavailable (red). It refreshes every 8 seconds.

---

## Stopping the Lab

```powershell
docker compose down
```

This stops and removes all containers and networks. Your files and `.env` are not affected.

---

## Troubleshooting

### Dashboard shows "Reconnecting…" in the top-right
The ai-gateway container may still be starting. Wait 30 seconds and refresh.

### Falco logs show errors about eBPF / BPF probe
1. Make sure WSL 2 integration is enabled in Docker Desktop settings
2. Try restarting Docker Desktop and running `docker compose up -d` again

### Attack triggers return "Error" in the dashboard
The attacker containers may not have finished starting. Run:

```powershell
docker ps
```

All containers should show **Up** status. If any show **Restarting**, check logs:

```powershell
docker logs attacker-escape
```

### No alert cards appear after triggering
Check the ai-gateway logs to see if Falco is sending alerts:

```powershell
docker logs ai-gateway --tail 50
```

If you see `[ANALYSIS ERROR]`, the OpenAI API key in `.env` may be incorrect or exhausted.

---

## CLI Alternative (no browser needed)

If you prefer the command line, use `trigger.py`:

```powershell
# Install dependencies (once)
pip install requests

# Check all attacker containers are healthy
python trigger.py --health

# Trigger a single attack
python trigger.py --attack escape

# Trigger all 5 attacks with 10-second gaps
python trigger.py --attack all
```

AI analysis output appears in the ai-gateway container logs:

```powershell
docker logs ai-gateway -f
```
