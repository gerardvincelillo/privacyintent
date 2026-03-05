
"""Privacy scoring logic."""

from __future__ import annotations

from privacy_intent.models import Finding, ScanReport

SEVERITY_WEIGHTS = {
    "low": 3,
    "medium": 8,
    "high": 15,
    "critical": 25,
}

CONFIDENCE_MULTIPLIER = {
    "low": 0.7,
    "med": 1.0,
    "high": 1.2,
}


def _risk_rank(finding: Finding) -> tuple[int, float]:
    sev = {"low": 0, "medium": 1, "high": 2, "critical": 3}[finding.severity]
    conf = {"low": 0.7, "med": 1.0, "high": 1.2}[finding.confidence]
    return sev, conf


def apply_privacy_score(report: ScanReport) -> ScanReport:
    total_penalty = 0.0
    for finding in report.findings:
        weight = SEVERITY_WEIGHTS[finding.severity]
        multiplier = CONFIDENCE_MULTIPLIER[finding.confidence]
        total_penalty += weight * multiplier

    report.score = max(0, min(100, round(100 - total_penalty)))
    report.top_risks = sorted(report.findings, key=_risk_rank, reverse=True)[:3]
    return report

