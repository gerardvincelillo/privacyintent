import json

from privacy_intent.models import Finding, ScanArtifacts, ScanReport
from privacy_intent.reporting.sarif_report import write_report


def test_write_sarif_report(tmp_path) -> None:
    report = ScanReport(
        artifacts=ScanArtifacts(root_url="https://example.com", visited_urls=["https://example.com"]),
        findings=[
            Finding(
                id="pii-query-leak",
                severity="high",
                category="pii",
                description="Potential PII in query parameters.",
                evidence="email=john@example.com",
                recommendation="Avoid sending PII in query strings.",
                confidence="high",
            )
        ],
        score=70,
    )
    target = tmp_path / "report.sarif.json"
    write_report(target, report)
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"][0]["ruleId"] == "pii-query-leak"
