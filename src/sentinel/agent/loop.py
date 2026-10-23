"""The deterministic MVP does not delegate network access to an LLM."""
from sentinel.agent.planner import parse_plan

def bounded_plan(text, retries=2):
    for _ in range(retries):
        try: return parse_plan(text)
        except (ValueError, TypeError): pass
    return None
