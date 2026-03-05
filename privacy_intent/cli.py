
"""CLI entrypoint for PrivacyIntent."""

from __future__ import annotations

import json as json_lib
from pathlib import Path
from typing import Optional

import typer

from privacy_intent.automation import build_auto_report_paths, normalize_target_url, resolve_scan_options
from privacy_intent.bootstrap import init_workspace
from privacy_intent.reporting.diff_report import compare_reports
from privacy_intent.scanner import scan_site

app = typer.Typer(help="PrivacyIntent CLI for website privacy auditing.")
ci_app = typer.Typer(help="PrivacyIntent CI gate commands (requires PrivacyIntent Pro).")
monitor_app = typer.Typer(help="PrivacyIntent monitoring and drift commands.")


@app.callback()
def main() -> None:
    """Root command group for PrivacyIntent."""


@app.command("scan")
def scan(
    url: str,
    json: Optional[Path] = typer.Option(
        None,
        "--json",
        help="Write a JSON report to the given path.",
    ),
    md: Optional[Path] = typer.Option(
        None,
        "--md",
        help="Write a Markdown report to the given path.",
    ),
    sarif: Optional[Path] = typer.Option(
        None,
        "--sarif",
        help="Write a SARIF report to the given path.",
    ),
    timeout: Optional[int] = typer.Option(None, "--timeout", min=1, help="Request timeout in seconds."),
    max_requests: Optional[int] = typer.Option(
        None,
        "--max-requests",
        min=1,
        help="Maximum number of requests to collect.",
    ),
    headless: bool = typer.Option(True, "--headless/--no-headless", help="Run browser headless."),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Override browser user agent."),
    depth: Optional[int] = typer.Option(None, "--depth", min=0, help="Basic crawl depth."),
    profile: str = typer.Option("standard", "--profile", help="Scan profile: quick|standard|deep."),
    artifacts_dir: Optional[Path] = typer.Option(
        None,
        "--artifacts-dir",
        help="Auto-generate JSON/Markdown reports in this directory when no --json/--md is provided.",
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Disable console scan summary output."),
) -> None:
    """Scan a URL for privacy risks."""
    normalized_url = normalize_target_url(url)
    effective_timeout, effective_max_requests, effective_depth = resolve_scan_options(
        profile=profile,
        timeout=timeout,
        max_requests=max_requests,
        depth=depth,
    )

    json_path = json
    md_path = md
    sarif_path = sarif
    if artifacts_dir is not None and json_path is None and md_path is None:
        json_path, md_path = build_auto_report_paths(normalized_url, artifacts_dir)
        sarif_path = artifacts_dir / f"{json_path.stem}.sarif.json"

    scan_site(
        url=normalized_url,
        json_path=json_path,
        md_path=md_path,
        sarif_path=sarif_path,
        timeout=effective_timeout,
        max_requests=effective_max_requests,
        headless=headless,
        user_agent=user_agent,
        depth=effective_depth,
        print_console_output=not quiet,
    )


@app.command("compare")
def compare(
    baseline: Path = typer.Argument(..., exists=True, dir_okay=False, help="Baseline JSON report path."),
    current: Path = typer.Argument(..., exists=True, dir_okay=False, help="Current JSON report path."),
    json: Optional[Path] = typer.Option(None, "--json", help="Write comparison JSON output."),
) -> None:
    """Compare two JSON scan reports and summarize privacy drift."""
    baseline_report = json_lib.loads(baseline.read_text(encoding="utf-8"))
    current_report = json_lib.loads(current.read_text(encoding="utf-8"))
    result = compare_reports(baseline_report, current_report)

    typer.echo("Privacy Drift Summary")
    typer.echo(f"- Score: {result['baseline_score']} -> {result['current_score']} ({result['score_delta']:+d})")
    typer.echo(
        f"- Findings: {result['baseline_total_findings']} -> "
        f"{result['current_total_findings']} ({result['total_findings_delta']:+d})"
    )
    typer.echo(f"- New High/Critical Findings: {result['new_high_or_critical']}")
    if result["new_categories"]:
        typer.echo(f"- New Categories: {', '.join(result['new_categories'])}")
    if result["new_finding_ids"]:
        typer.echo("- New Finding IDs:")
        for finding_id in result["new_finding_ids"]:
            typer.echo(f"  - {finding_id}")

    if json is not None:
        json.parent.mkdir(parents=True, exist_ok=True)
        json.write_text(json_lib.dumps(result, indent=2), encoding="utf-8")


@ci_app.command("scan")
def ci_scan(
    url: str,
    min_score: int = typer.Option(75, "--min-score", min=0, max=100, help="Minimum passing privacy score."),
    policy: Optional[Path] = typer.Option(None, "--policy", help="Optional policy file path."),
    json: Optional[Path] = typer.Option(None, "--json", help="Write a JSON report to the given path."),
    md: Optional[Path] = typer.Option(None, "--md", help="Write a Markdown report to the given path."),
    sarif: Optional[Path] = typer.Option(None, "--sarif", help="Write a SARIF report to the given path."),
    gate_json: Optional[Path] = typer.Option(None, "--gate-json", help="Write CI gate result JSON to path."),
    artifacts_dir: Optional[Path] = typer.Option(
        None,
        "--artifacts-dir",
        help="Auto-generate scan and gate artifacts in this directory when paths are omitted.",
    ),
    timeout: Optional[int] = typer.Option(None, "--timeout", min=1, help="Request timeout in seconds."),
    max_requests: Optional[int] = typer.Option(None, "--max-requests", min=1, help="Maximum number of requests to collect."),
    headless: bool = typer.Option(True, "--headless/--no-headless", help="Run browser headless."),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Override browser user agent."),
    depth: Optional[int] = typer.Option(None, "--depth", min=0, help="Basic crawl depth."),
    profile: str = typer.Option("standard", "--profile", help="Scan profile: quick|standard|deep."),
) -> None:
    """Run a CI-oriented scan and fail on policy/score violations."""
    if policy is not None and not policy.exists():
        typer.echo(f"CI gate policy error: Policy file not found: {policy}")
        raise typer.Exit(code=2)

    normalized_url = normalize_target_url(url)
    effective_timeout, effective_max_requests, effective_depth = resolve_scan_options(
        profile=profile,
        timeout=timeout,
        max_requests=max_requests,
        depth=depth,
    )

    json_path = json
    md_path = md
    sarif_path = sarif
    gate_json_path = gate_json
    if artifacts_dir is not None:
        if json_path is None and md_path is None:
            json_path, md_path = build_auto_report_paths(normalized_url, artifacts_dir)
            sarif_path = artifacts_dir / f"{json_path.stem}.sarif.json"
        if gate_json_path is None:
            gate_json_path = artifacts_dir / "ci_gate_result.json"

    report = scan_site(
        url=normalized_url,
        json_path=json_path,
        md_path=md_path,
        sarif_path=sarif_path,
        timeout=effective_timeout,
        max_requests=effective_max_requests,
        headless=headless,
        user_agent=user_agent,
        depth=effective_depth,
        print_console_output=True,
    )

    try:
        from privacy_intent_pro.ci_gate import run_ci_gate
    except Exception as exc:
        typer.echo(
            "PrivacyIntent Pro is required for `privacyintent ci scan`. "
            "Install privacyintent-pro and retry."
        )
        raise typer.Exit(code=2) from exc

    try:
        gate_result = run_ci_gate(report=report, min_score=min_score, policy_path=policy)
    except FileNotFoundError as exc:
        typer.echo(f"CI gate policy error: {exc}")
        raise typer.Exit(code=2) from exc
    except (RuntimeError, ValueError) as exc:
        typer.echo(f"CI gate execution error: {exc}")
        raise typer.Exit(code=2) from exc
    status = gate_result.get("status", "fail")
    violations = gate_result.get("violations", [])

    typer.echo("")
    typer.echo("CI Gate Summary")
    typer.echo(f"- Status: {status.upper()}")
    typer.echo(f"- Score: {gate_result.get('score')}/100")
    typer.echo(f"- Required Minimum: {gate_result.get('effective_min_score')}")
    if gate_result.get("policy_path"):
        typer.echo(f"- Policy: {gate_result.get('policy_path')}")
    if violations:
        typer.echo("- Violations:")
        for violation in violations:
            typer.echo(f"  - {violation}")
    if gate_json_path is not None:
        gate_json_path.parent.mkdir(parents=True, exist_ok=True)
        gate_json_path.write_text(json_lib.dumps(gate_result, indent=2), encoding="utf-8")
        typer.echo(f"- Gate JSON: {gate_json_path}")

    if status != "pass":
        raise typer.Exit(code=1)


@app.command("init")
def init(
    path: Path = typer.Option(Path("."), "--path", help="Target directory to initialize."),
    force: bool = typer.Option(False, "--force", help="Overwrite existing starter files."),
) -> None:
    """Create starter config, policy, and report artifact paths."""
    result = init_workspace(path.resolve(), force=force)
    typer.echo("PrivacyIntent workspace initialized")
    typer.echo(f"- Path: {path.resolve()}")
    typer.echo(f"- Created: {len(result['created'])}")
    for item in result["created"]:
        typer.echo(f"  - {item}")
    if result["skipped"]:
        typer.echo(f"- Skipped: {len(result['skipped'])}")


@monitor_app.command("diff")
def monitor_diff(
    baseline: Path = typer.Option(..., "--baseline", exists=True, dir_okay=False, help="Baseline JSON report path."),
    current: Path = typer.Option(..., "--current", exists=True, dir_okay=False, help="Current JSON report path."),
    json: Optional[Path] = typer.Option(None, "--json", help="Write drift JSON output."),
    fail_on_regression: bool = typer.Option(
        False,
        "--fail-on-regression",
        help="Exit with code 1 when regression is detected.",
    ),
) -> None:
    """Compare two reports and optionally fail if privacy posture regresses."""
    baseline_report = json_lib.loads(baseline.read_text(encoding="utf-8"))
    current_report = json_lib.loads(current.read_text(encoding="utf-8"))
    result = compare_reports(baseline_report, current_report)

    regression_reasons: list[str] = []
    if int(result.get("score_delta", 0)) < 0:
        regression_reasons.append("Privacy score decreased.")
    if int(result.get("new_high_or_critical", 0)) > 0:
        regression_reasons.append("New high/critical findings detected.")
    regression = bool(regression_reasons)
    result["regression"] = regression
    result["regression_reasons"] = regression_reasons

    typer.echo("Monitor Drift Summary")
    typer.echo(f"- Regression: {'YES' if regression else 'NO'}")
    typer.echo(f"- Score delta: {result.get('score_delta', 0):+d}")
    typer.echo(f"- New High/Critical: {result.get('new_high_or_critical', 0)}")
    if regression_reasons:
        typer.echo("- Reasons:")
        for reason in regression_reasons:
            typer.echo(f"  - {reason}")

    if json is not None:
        json.parent.mkdir(parents=True, exist_ok=True)
        json.write_text(json_lib.dumps(result, indent=2), encoding="utf-8")
    if fail_on_regression and regression:
        raise typer.Exit(code=1)


app.add_typer(ci_app, name="ci")
app.add_typer(monitor_app, name="monitor")


if __name__ == "__main__":
    app()


