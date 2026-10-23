"""Optional planner contract. No provider is contacted unless explicitly configured."""
import json
from dataclasses import dataclass
from sentinel.tools.registry import validate_action

@dataclass
class Plan:
    action: str
    arguments: dict
    rationale: str

def parse_plan(text):
    data=json.loads(text)
    if not isinstance(data,dict) or set(data)!={"action","arguments","rationale"} or not isinstance(data["rationale"],str):
        raise ValueError("planner response has invalid schema")
    if data["action"]!="stop": validate_action(data["action"],data["arguments"])
    return Plan(**data)
