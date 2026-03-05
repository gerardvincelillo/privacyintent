
"""Markdown report writer."""

from __future__ import annotations

from pathlib import Path

from privacy_intent.models import ScanReport


def write_report(path: Path, report: ScanReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# PrivacyIntent Report",
        "",
        f"- Target: `{report.artifacts.root_url}`",
        f"- Score: **{report.score}/100**",
        f"- Findings: **{len(report.findings)}**",
        "",
        "## Top Risks",
        "",
    ]

    if not report.top_risks:
        lines.append("- No major risks identified.")
    else:
        for risk in report.top_risks:
            lines.append(f"- **[{risk.severity.upper()}] {risk.category}**: {risk.description}")

    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("- No findings.")
    else:
        for finding in report.findings:
            lines.append(f"### {finding.id}")
            lines.append(f"- Severity: `{finding.severity}`")
            lines.append(f"- Category: `{finding.category}`")
            lines.append(f"- Confidence: `{finding.confidence}`")
            lines.append(f"- Description: {finding.description}")
            lines.append(f"- Recommendation: {finding.recommendation}")
            lines.append(f"- Evidence: `{finding.evidence}`")
            lines.append("")

    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

