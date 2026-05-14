def triage_prompt(alert: dict) -> list[dict]:
    return [
        {
            "role": "system",
            "content": (
                "You are a container security triage analyst. "
                "Respond with exactly ONE sentence in this format: "
                "[SEVERITY: LOW|MEDIUM|HIGH|CRITICAL] <what happened in plain English>."
            ),
        },
        {"role": "user", "content": f"Falco alert JSON: {alert}"},
    ]


def deep_prompt(alert: dict) -> list[dict]:
    return [
        {
            "role": "system",
            "content": (
                "You are a senior container security expert. "
                "Given a Falco alert, respond with a JSON object containing exactly these keys:\n"
                "- mitre_technique: MITRE ATT&CK technique ID and name (e.g. T1611 - Escape to Host)\n"
                "- what_happened: 2-3 sentence plain-English explanation\n"
                "- misconfiguration: the exact Docker/container config that enabled this attack\n"
                "- predicted_next_move: what the attacker will likely do next (1 sentence)\n"
                "- risk_score: integer 0-10\n"
                "- hardened_config: the corrected Docker Compose snippet that prevents this attack\n"
                "Respond with ONLY the JSON object, no markdown fences."
            ),
        },
        {"role": "user", "content": f"Falco alert JSON: {alert}"},
    ]
