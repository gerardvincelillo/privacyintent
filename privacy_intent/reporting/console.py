
"""Rich console reporting."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from privacy_intent.models import ScanReport

SEVERITY_STYLE = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}

console = Console()


def print_summary(report: ScanReport) -> None:
    stats = Table(title="PrivacyIntent Summary")
    stats.add_column("Metric")
    stats.add_column("Value", justify="right")
    stats.add_row("Target", report.artifacts.root_url)
    stats.add_row("Visited URLs", str(len(report.artifacts.visited_urls)))
    stats.add_row("Requests", str(len(report.artifacts.requests)))
    stats.add_row("Responses", str(len(report.artifacts.responses)))
    stats.add_row("Cookies", str(len(report.artifacts.cookies)))
    stats.add_row("Findings", str(len(report.findings)))
    stats.add_row("Privacy Score", f"[bold]{report.score}/100[/bold]")
    console.print(stats)

    if report.top_risks:
        risks = Table(title="Top Risks")
        risks.add_column("ID")
        risks.add_column("Severity")
        risks.add_column("Category")
        risks.add_column("Description")
        for finding in report.top_risks:
            style = SEVERITY_STYLE.get(finding.severity, "white")
            risks.add_row(
                finding.id,
                f"[{style}]{finding.severity}[/{style}]",
                finding.category,
                finding.description,
            )
        console.print(risks)
    else:
        console.print(Panel("No major risks identified.", title="Top Risks"))

