from pathlib import Path
from sentinel.models import ScanResult

def render(result: ScanResult) -> str:
    counts={x:sum(1 for c in result.checks if c.status==x) for x in ("confirmed","potential","inconclusive","skipped","failed")}
    out=["# Sentinel Security Scan Report", "", "> Bounded educational scan. Authorization is the operator's responsibility. This is not a professional assessment or proof of security.","", "## Summary", "", f"- Target: `{result.target}`", f"- Mode: {result.mode}", f"- Started: {result.started_at}", f"- Checks: {len(result.checks)}; confirmed {counts['confirmed']}, potential {counts['potential']}, inconclusive {counts['inconclusive']}, skipped {counts['skipped']}, failed {counts['failed']}","", "## Checks and observations",""]
    for c in result.checks:
        out += [f"### {c.check_id} — {c.status} ({c.severity}, confidence {c.confidence})", "", c.summary]
        if c.evidence_ids: out.append("Evidence: "+", ".join(f"`{e}`" for e in c.evidence_ids))
        if c.remediation: out.append("Remediation: "+c.remediation)
        out.append("")
    out += ["## Evidence",""]
    for e in result.evidence: out.append(f"- **{e.id}** ({e.source}) {e.description}: `{e.value}`")
    if result.llm_analysis:
        analysis=result.llm_analysis
        out += ["", "## LLM analysis", "", analysis["summary"], "", "### Priority findings", ""]
        out += [f"- {item}" for item in analysis["priority_findings"]] or ["- None identified from supplied evidence."]
        out += ["", "### Recommended next steps", ""]
        out += [f"- {item}" for item in analysis["recommended_next_steps"]] or ["- No additional steps recommended from supplied evidence."]
        out += ["", "### Caveats", ""]
        out += [f"- {item}" for item in analysis["caveats"]] or ["- The analysis is limited to supplied evidence."]
    out += ["", "## Limitations", "", "Only bounded passive HTTP checks ran. Authentication, application-specific logic, complete TLS certificate analysis, and exhaustive endpoint discovery are not assessed. Missing headers are observations, not proof of a vulnerability.",""]
    return "\n".join(out)

def write_markdown(result: ScanResult, path: Path):
    path.write_text(render(result),encoding="utf-8")
