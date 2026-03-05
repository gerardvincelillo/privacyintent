from privacy_intent.reporting.diff_report import compare_reports


def test_compare_reports_detects_new_findings_and_score_delta() -> None:
    baseline = {
        "score": 82,
        "findings": [
            {"id": "cookie-001", "severity": "medium", "category": "cookies"},
            {"id": "hdr-001", "severity": "low", "category": "headers"},
        ],
    }
    current = {
        "score": 74,
        "findings": [
            {"id": "cookie-001", "severity": "medium", "category": "cookies"},
            {"id": "hdr-001", "severity": "low", "category": "headers"},
            {"id": "pii-009", "severity": "high", "category": "pii"},
        ],
    }

    result = compare_reports(baseline, current)

    assert result["score_delta"] == -8
    assert result["new_finding_ids"] == ["pii-009"]
    assert result["new_high_or_critical"] == 1
    assert result["new_category_counts"] == {"pii": 1}
