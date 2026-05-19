import asyncio
import time

subscribers: list[asyncio.Queue] = []
recent_alerts: list[dict] = []
falco_logs: list[dict] = []
attack_logs: list[dict] = []

# Deduplication: track last broadcast time per rule to suppress near-identical
# alerts fired by a single attack run (e.g. multiple cd /proc/self/fd invocations).
_last_seen: dict[str, float] = {}
DEDUP_WINDOW = 5.0  # seconds


def _append_capped(lst: list, item: dict, cap: int = 100) -> None:
    lst.append(item)
    if len(lst) > cap:
        lst.pop(0)


async def broadcast(data: dict) -> None:
    rule = data.get("rule", "")
    now = time.monotonic()
    if now - _last_seen.get(rule, 0.0) < DEDUP_WINDOW:
        return
    _last_seen[rule] = now

    _append_capped(recent_alerts, data)
    for q in subscribers:
        await q.put(data)


def log_falco(raw: dict) -> None:
    _append_capped(falco_logs, raw)


def log_attack(entry: dict) -> None:
    _append_capped(attack_logs, entry)
