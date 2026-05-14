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
