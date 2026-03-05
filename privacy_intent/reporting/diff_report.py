"""Diff utility for comparing scan reports."""

from __future__ import annotations

from collections import Counter
from typing import Any


def _findings_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    findings = report.get("findings", [])
    mapped: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if isinstance(finding, dict):
            finding_id = str(finding.get("id", "")).strip()
            if finding_id:
                mapped[finding_id] = finding
    return mapped


def compare_reports(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare baseline and current scan reports and return drift summary."""
    baseline_findings = _findings_map(baseline)
    current_findings = _findings_map(current)

    new_ids = sorted(set(current_findings) - set(baseline_findings))
    new_findings = [current_findings[finding_id] for finding_id in new_ids]
    new_high_or_critical = sum(
        1 for finding in new_findings if str(finding.get("severity", "")).lower() in {"high", "critical"}
    )

    baseline_score = int(baseline.get("score", 0))
    current_score = int(current.get("score", 0))

    category_counts = Counter(str(finding.get("category", "unknown")) for finding in new_findings)

    return {
        "baseline_score": baseline_score,
        "current_score": current_score,
        "score_delta": current_score - baseline_score,
        "baseline_total_findings": len(baseline.get("findings", [])),
        "current_total_findings": len(current.get("findings", [])),
        "total_findings_delta": len(current.get("findings", [])) - len(baseline.get("findings", [])),
        "new_finding_ids": new_ids,
        "new_high_or_critical": new_high_or_critical,
        "new_categories": sorted(category_counts),
        "new_category_counts": dict(category_counts),
    }
