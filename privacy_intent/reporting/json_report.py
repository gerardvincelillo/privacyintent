
"""JSON report writer."""

from __future__ import annotations

from pathlib import Path

from privacy_intent.models import ScanReport


def write_report(path: Path, report: ScanReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

