import asyncio
import json
import logging
import litellm
from prompts import triage_prompt, deep_prompt

logger = logging.getLogger(__name__)

TRIAGE_MODEL = "openai/gpt-5.4-nano"
ANALYSIS_MODEL = "openai/gpt-5.5"

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
                model=TRIAGE_MODEL,
                messages=triage_prompt(alert),
                max_tokens=80,
            ),
            litellm.acompletion(
                model=ANALYSIS_MODEL,
                messages=deep_prompt(alert),
                max_tokens=1200,
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
        logger.warning("Deep model returned empty content for rule '%s' (finish_reason=%s)", rule, finish_reason)

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
