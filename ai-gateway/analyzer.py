import asyncio
import json
import logging
import re
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

# Falco container.label.scenario is null in this setup because the container
# plugin doesn't surface Docker labels into Falco output fields. We resolve the
# scenario from the rule name instead, same as the dashboard does client-side.
RULE_TO_SCENARIO: dict[str, str] = {
    "Container Escape via runc fd Leak": "escape",
    "Docker Socket Access from Container": "sock",
    "New Privileged Container Created via Socket": "sock",
    "Lateral Movement via nsenter": "lateral",
    "Unexpected Internal Network Scan": "lateral",
    "Sensitive File Read in Container": "secrets",
    "Process Environment Dump": "secrets",
    "Docker AuthZ Bypass via Oversized Request": "authz",
}

_SEVERITY_RE = re.compile(r"\[SEVERITY:\s*(CRITICAL|HIGH|MEDIUM|LOW)\]")


def _resolve_scenario(alert: dict) -> str:
    label = alert.get("output_fields", {}).get("container.label.scenario")
    if label:
        return label
    rule = alert.get("rule", "")
    for prefix, scenario in RULE_TO_SCENARIO.items():
        if rule.startswith(prefix):
            return scenario
    return alert.get("hostname", "unknown")


def _extract_severity(triage_text: str) -> str:
    m = _SEVERITY_RE.search(triage_text)
    if m:
        return m.group(1)
    # fallback: check for bare keyword (AI didn't follow the format exactly)
    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if lvl in triage_text:
            return lvl
    return "MEDIUM"


async def analyze_alert(alert: dict) -> None:
    scenario = _resolve_scenario(alert)
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

    severity = _extract_severity(triage_text)
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
