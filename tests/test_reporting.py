from sentinel.models import ScanResult,CheckResult,Evidence
from sentinel.reporting.markdown import render

def test_report_links_evidence_and_states_limitations():
    r=ScanResult("1","id","now","now","http://localhost",{},"deterministic",[],[CheckResult("x","potential","Observed",evidence_ids=["E1"])],[Evidence("E1","test","fact","safe")])
    text=render(r)
    assert "`E1`" in text and "**E1**" in text and "not proof" in text


def test_report_includes_llm_analysis_when_present():
    r=ScanResult("1","id","now","now","http://localhost",{},"deterministic",[],[],[],[],{"summary":"safe","priority_findings":["Review CSP"],"recommended_next_steps":["Validate in staging"],"caveats":["Passive evidence only"]})
    text=render(r)
    assert "## LLM analysis" in text and "Review CSP" in text
