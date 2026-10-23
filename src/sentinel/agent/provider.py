"""Optional Gemini analysis over already-collected, sanitized scan facts."""
import json
import os
from dataclasses import asdict
from typing import Any

from sentinel.agent.prompts import ANALYST_SYSTEM_PROMPT

ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "priority_findings": {"type": "array", "items": {"type": "string"}},
        "recommended_next_steps": {"type": "array", "items": {"type": "string"}},
        "caveats": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "priority_findings", "recommended_next_steps", "caveats"],
    "additionalProperties": False,
}


def _validate_analysis(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("LLM analysis must be an object")
    required = set(ANALYSIS_SCHEMA["required"])
    if set(value) != required or not isinstance(value["summary"], str):
        raise ValueError("LLM analysis has invalid schema")
    for key in required - {"summary"}:
        if not isinstance(value[key], list) or not all(isinstance(item, str) for item in value[key]):
            raise ValueError("LLM analysis lists must contain only strings")
    return value


def analyze_scan(observations: list[dict], checks: list[Any], evidence: list[Any], model: str) -> dict[str, Any]:
    """Ask the configured provider to interpret facts without granting tool access."""
    try:
        from google import genai
    except ImportError as exc:
        raise RuntimeError("LLM support requires the 'llm' extra: pip install -e '.[llm]'") from exc

    api_key = os.getenv("SENTINEL_LLM_API_KEY") or os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("LLM analysis requires SENTINEL_LLM_API_KEY or GEMINI_API_KEY")

    payload = {
        "observations": observations,
        "checks": [asdict(item) for item in checks],
        "evidence": [asdict(item) for item in evidence],
    }
    client = genai.Client(api_key=api_key)
    try:
        response = client.models.generate_content(
            model=model,
            contents=ANALYST_SYSTEM_PROMPT + "\n\nSCAN_FACTS_JSON:\n" + json.dumps(payload, ensure_ascii=False),
            config={
                "response_mime_type": "application/json",
                "response_json_schema": ANALYSIS_SCHEMA,
            },
        )
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()
    try:
        parsed = json.loads(response.text)
    except (AttributeError, json.JSONDecodeError) as exc:
        raise RuntimeError("LLM returned invalid analysis output") from exc
    return _validate_analysis(parsed)
