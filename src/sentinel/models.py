"""Typed-enough immutable records shared by scanner, checks, and reports."""
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Evidence:
    id: str
    source: str
    description: str
    value: Any = None


@dataclass
class CheckResult:
    check_id: str
    status: str
    summary: str
    severity: str = "info"
    confidence: str = "high"
    evidence_ids: list[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class ScanResult:
    schema_version: str
    scan_id: str
    started_at: str
    finished_at: str
    target: str
    scope: dict[str, Any]
    mode: str
    observations: list[dict[str, Any]]
    checks: list[CheckResult]
    evidence: list[Evidence]
    errors: list[str] = field(default_factory=list)
    llm_analysis: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
