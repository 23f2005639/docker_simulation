import asyncio
import json

import httpx
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import FileResponse
from sse_starlette.sse import EventSourceResponse

from analyzer import analyze_alert
from state import subscribers, recent_alerts

app = FastAPI(title="Falco AI Gateway")

ATTACKERS = {
    "escape": "http://host.docker.internal:5001",
    "sock": "http://host.docker.internal:5002",
    "lateral": "http://host.docker.internal:5003",
    "secrets": "http://host.docker.internal:5004",
    "authz": "http://host.docker.internal:5005",
}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/falco-alert")
async def falco_alert(request: Request, background_tasks: BackgroundTasks):
    alert = await request.json()
    background_tasks.add_task(analyze_alert, alert)
    return {"status": "received", "rule": alert.get("rule")}


@app.get("/dashboard")
async def dashboard():
    return FileResponse("/app/dashboard.html")


@app.get("/api/alerts")
async def get_alerts():
    return recent_alerts


@app.get("/api/health")
async def get_system_health():
    results = {}
    async with httpx.AsyncClient(timeout=3.0) as client:
        for name, base_url in ATTACKERS.items():
            try:
                r = await client.get(f"{base_url}/health")
                results[name] = r.json() if r.status_code == 200 else {"status": "error"}
            except Exception:
                results[name] = {"status": "unreachable"}
    return results


@app.post("/api/trigger/{scenario}")
async def trigger_attack(scenario: str):
    base_url = ATTACKERS.get(scenario)
    if not base_url:
        return {"status": "error", "message": f"Unknown scenario: {scenario}"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.post(f"{base_url}/trigger")
            return r.json()
        except Exception as exc:
            return {"status": "error", "message": str(exc)}


@app.get("/stream")
async def stream(request: Request):
    queue: asyncio.Queue = asyncio.Queue()
    subscribers.append(queue)

    async def generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=30)
                    yield {"data": json.dumps(data)}
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": ""}
        finally:
            if queue in subscribers:
                subscribers.remove(queue)

    return EventSourceResponse(generator())
