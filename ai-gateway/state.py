import asyncio

subscribers: list[asyncio.Queue] = []
recent_alerts: list[dict] = []
falco_logs: list[dict] = []
attack_logs: list[dict] = []


def _append_capped(lst: list, item: dict, cap: int = 100) -> None:
    lst.append(item)
    if len(lst) > cap:
        lst.pop(0)


async def broadcast(data: dict) -> None:
    _append_capped(recent_alerts, data)
    for q in subscribers:
        await q.put(data)


def log_falco(raw: dict) -> None:
    _append_capped(falco_logs, raw)


def log_attack(entry: dict) -> None:
    _append_capped(attack_logs, entry)
