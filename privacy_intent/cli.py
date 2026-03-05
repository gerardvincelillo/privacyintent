
"""CLI entrypoint for PrivacyIntent."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from privacy_intent.scanner import scan_site

app = typer.Typer(help="PrivacyIntent CLI for website privacy auditing.")
ci_app = typer.Typer(help="PrivacyIntent CI gate commands (requires PrivacyIntent Pro).")


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
    timeout: int = typer.Option(30, "--timeout", min=1, help="Request timeout in seconds."),
    max_requests: int = typer.Option(
        200,
        "--max-requests",
        min=1,
        help="Maximum number of requests to collect.",
    ),
    headless: bool = typer.Option(True, "--headless/--no-headless", help="Run browser headless."),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Override browser user agent."),
    depth: int = typer.Option(0, "--depth", min=0, help="Basic crawl depth."),
) -> None:
    """Scan a URL for privacy risks."""
    scan_site(
        url=url,
        json_path=json,
        md_path=md,
        timeout=timeout,
        max_requests=max_requests,
        headless=headless,
        user_agent=user_agent,
        depth=depth,
    )


@ci_app.command("scan")
def ci_scan(
    url: str,
    min_score: int = typer.Option(75, "--min-score", min=0, max=100, help="Minimum passing privacy score."),
    policy: Optional[Path] = typer.Option(None, "--policy", help="Optional policy file path."),
    json: Optional[Path] = typer.Option(None, "--json", help="Write a JSON report to the given path."),
    md: Optional[Path] = typer.Option(None, "--md", help="Write a Markdown report to the given path."),
    timeout: int = typer.Option(30, "--timeout", min=1, help="Request timeout in seconds."),
    max_requests: int = typer.Option(200, "--max-requests", min=1, help="Maximum number of requests to collect."),
    headless: bool = typer.Option(True, "--headless/--no-headless", help="Run browser headless."),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Override browser user agent."),
    depth: int = typer.Option(0, "--depth", min=0, help="Basic crawl depth."),
) -> None:
    """Run a CI-oriented scan and fail on policy/score violations."""
    if policy is not None and not policy.exists():
        typer.echo(f"CI gate policy error: Policy file not found: {policy}")
        raise typer.Exit(code=2)

    report = scan_site(
        url=url,
        json_path=json,
        md_path=md,
        timeout=timeout,
        max_requests=max_requests,
        headless=headless,
        user_agent=user_agent,
        depth=depth,
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

    if status != "pass":
        raise typer.Exit(code=1)


app.add_typer(ci_app, name="ci")


if __name__ == "__main__":
    app()


