import json

from typer.testing import CliRunner

from privacy_intent.cli import app

runner = CliRunner()


def test_monitor_diff_fails_on_regression(tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    baseline.write_text(json.dumps({"score": 90, "findings": [{"id": "a", "severity": "low", "category": "headers"}]}))
    current.write_text(
        json.dumps(
            {
                "score": 70,
                "findings": [
                    {"id": "a", "severity": "low", "category": "headers"},
                    {"id": "b", "severity": "high", "category": "pii"},
                ],
            }
        )
    )

    result = runner.invoke(
        app,
        [
            "monitor",
            "diff",
            "--baseline",
            str(baseline),
            "--current",
            str(current),
            "--fail-on-regression",
        ],
    )
    assert result.exit_code == 1
    assert "Regression: YES" in result.output
