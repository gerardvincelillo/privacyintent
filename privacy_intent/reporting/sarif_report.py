"""SARIF report writer."""

from __future__ import annotations

import json
from pathlib import Path

from privacy_intent.models import Finding, ScanReport

_SEVERITY_TO_LEVEL = {
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


def _rule_from_finding(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "name": finding.id,
        "shortDescription": {"text": finding.description[:120]},
        "fullDescription": {"text": finding.description},
        "properties": {
            "category": finding.category,
            "confidence": finding.confidence,
            "recommendation": finding.recommendation,
        },
    }


def _result_from_finding(finding: Finding) -> dict:
    return {
        "ruleId": finding.id,
        "level": _SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
        "message": {"text": finding.description},
        "properties": {
            "severity": finding.severity,
            "category": finding.category,
            "confidence": finding.confidence,
            "evidence": finding.evidence,
        },
    }


def write_report(path: Path, report: ScanReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rules_seen = set()
    rules = []
    for finding in report.findings:
        if finding.id in rules_seen:
            continue
        rules_seen.add(finding.id)
        rules.append(_rule_from_finding(finding))

    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "privacyintent",
                        "informationUri": "https://github.com/gerardvincelillo/privacy-intent",
                        "rules": rules,
                    }
                },
                "results": [_result_from_finding(finding) for finding in report.findings],
                "properties": {
                    "score": report.score,
                    "root_url": report.artifacts.root_url,
                    "visited_urls": report.artifacts.visited_urls,
                },
            }
        ],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
