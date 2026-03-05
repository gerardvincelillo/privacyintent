"""Project bootstrap helpers for PrivacyIntent automation."""

from __future__ import annotations

from pathlib import Path

DEFAULT_CONFIG = """# PrivacyIntent local defaults
scan:
  profile: standard
  timeout: 30
  max_requests: 200
  depth: 0
ci:
  min_score: 75
"""

DEFAULT_POLICY = """# PrivacyIntent baseline policy
min_score: 75
max_findings: 300
fail_on_severity:
  - critical
  - high
disallow_categories:
  - pii
"""


def _write_if_needed(path: Path, content: str, force: bool) -> bool:
    if path.exists() and not force:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


def init_workspace(root: Path, force: bool = False) -> dict[str, list[Path]]:
    """Create starter config/policy/artifacts paths for quick onboarding."""
    created: list[Path] = []
    skipped: list[Path] = []

    config_path = root / "privacyintent.yaml"
    policy_path = root / "policies" / "privacy_baseline.yaml"
    reports_dir = root / "reports"
    reports_keep = reports_dir / ".gitkeep"

    for path, content in [
        (config_path, DEFAULT_CONFIG),
        (policy_path, DEFAULT_POLICY),
        (reports_keep, ""),
    ]:
        if _write_if_needed(path, content, force):
            created.append(path)
        else:
            skipped.append(path)

    return {"created": created, "skipped": skipped}
