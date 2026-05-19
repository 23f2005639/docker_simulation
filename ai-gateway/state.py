import asyncio

subscribers: list[asyncio.Queue] = []
recent_alerts: list[dict] = []


async def broadcast(data: dict) -> None:
    recent_alerts.append(data)
    if len(recent_alerts) > 50:
        recent_alerts.pop(0)
    for q in subscribers:
        await q.put(data)
