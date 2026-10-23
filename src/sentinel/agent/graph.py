"""LangGraph orchestration for Sentinel's bounded multi-agent analysis."""
import operator
from dataclasses import asdict
from typing import Annotated, Any, TypedDict

from sentinel.agent.provider import analyze_scan


class SentinelState(TypedDict, total=False):
    target: str
    scope: Any
    observations: list[dict]
    checks: list[Any]
    evidence: list[Any]
    model: str
    scope_result: dict[str, Any]
    specialist_results: Annotated[dict[str, dict[str, Any]], operator.or_]
    llm_analysis: dict[str, Any]
    errors: list[str]


def _scope_agent(state: SentinelState) -> dict[str, Any]:
    """Validate the already-selected scope; never expand it."""
    permitted = bool(state["scope"].permits(state["target"]))
    model_review = analyze_scan(
        [{"agent": "scope", "target": state["target"], "deterministic_permitted": permitted}],
        [],
        [],
        state["model"],
    )
    return {
        "scope_result": {"permitted": permitted, "target": state["target"], "model_review": model_review},
        "errors": [] if permitted else ["target is outside the permitted scope"],
    }


def _specialist_agent(name: str, instruction: str):
    def run(state: SentinelState) -> dict[str, Any]:
        if state.get("errors"):
            return {"specialist_results": {name: {"status": "skipped", "reason": state["errors"][0]}}}
        facts = {
            "observations": state["observations"],
            "checks": [asdict(item) for item in state["checks"]],
            "evidence": [asdict(item) for item in state["evidence"]],
        }
        result = analyze_scan([{"specialist": name, "instruction": instruction, "facts": facts}], [], [], state["model"])
        return {"specialist_results": {name: result}}
    return run


def _hub_agent(state: SentinelState) -> dict[str, Any]:
    if state.get("errors"):
        return {"llm_analysis": None}
    combined = [{"specialist": "scope", "result": state.get("scope_result", {}).get("model_review")}]
    combined.extend({"specialist": name, "result": result} for name, result in state.get("specialist_results", {}).items())
    return {"llm_analysis": analyze_scan(combined, state["checks"], state["evidence"], state["model"])}


def build_graph():
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:
        raise RuntimeError("multi-agent mode requires the 'agents' extra: pip install -e '.[agents]'") from exc

    graph = StateGraph(SentinelState)
    graph.add_node("scope_agent", _scope_agent)
    graph.add_node("header_agent", _specialist_agent("headers", "Prioritize header-related observations."))
    graph.add_node("cookie_agent", _specialist_agent("cookies", "Prioritize cookie flag observations."))
    graph.add_node("transport_agent", _specialist_agent("transport", "Prioritize HTTPS and transport observations."))
    graph.add_node("hub_agent", _hub_agent)
    graph.add_edge(START, "scope_agent")
    graph.add_edge("scope_agent", "header_agent")
    graph.add_edge("scope_agent", "cookie_agent")
    graph.add_edge("scope_agent", "transport_agent")
    graph.add_edge(["header_agent", "cookie_agent", "transport_agent"], "hub_agent")
    graph.add_edge("hub_agent", END)
    return graph.compile()
