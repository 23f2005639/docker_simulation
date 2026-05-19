import asyncio
import json
import logging
from datetime import datetime, timezone

import litellm

from prompts import triage_prompt, deep_prompt
from state import broadcast

logger = logging.getLogger(__name__)

MODEL = "openai/gpt-4o"

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[94m",
    "LOW": "\033[92m",
}
RESET = "\033[0m"


async def analyze_alert(alert: dict) -> None:
    scenario = (
        alert.get("output_fields", {}).get("container.label.scenario")
        or alert.get("hostname", "unknown")
    )
    rule = alert.get("rule", "unknown-rule")

    try:
        triage_resp, deep_resp = await asyncio.gather(
            litellm.acompletion(
                model=MODEL,
                messages=triage_prompt(alert),
                max_tokens=60,
            ),
            litellm.acompletion(
                model=MODEL,
                messages=deep_prompt(alert),
                max_tokens=500,
                response_format={"type": "json_object"},
            ),
        )
    except Exception as exc:
        logger.error("LLM call failed for rule '%s': %s", rule, exc, exc_info=True)
        print(f"\n[ANALYSIS ERROR] rule={rule} error={exc}\n", flush=True)
        return

    triage_text = triage_resp.choices[0].message.content.strip()
    deep_raw = deep_resp.choices[0].message.content
    deep_text = deep_raw.strip() if deep_raw else ""

    if not deep_text:
        finish_reason = deep_resp.choices[0].finish_reason
        logger.warning(
            "Deep model returned empty content for rule '%s' (finish_reason=%s)",
            rule,
            finish_reason,
        )

    try:
        deep_json = json.loads(deep_text)
    except json.JSONDecodeError:
        deep_json = {"raw": deep_text}

    severity = "CRITICAL"
    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if lvl in triage_text:
            severity = lvl
            break

    color = SEVERITY_COLORS.get(severity, "")

    print(f"\n{color}{'='*60}{RESET}")
    print(f"{color}[{severity}] {scenario} — {rule}{RESET}")
    print(f"TRIAGE:   {triage_text}")
    print(f"ANALYSIS: {json.dumps(deep_json, indent=2)}")
    print(f"{color}{'='*60}{RESET}\n", flush=True)

    await broadcast(
        {
            "id": str(int(datetime.now(timezone.utc).timestamp() * 1000)),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "scenario": scenario,
            "rule": rule,
            "triage": triage_text,
            "analysis": deep_json,
        }
    )
