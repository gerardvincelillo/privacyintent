from pathlib import Path

from privacy_intent.automation import build_auto_report_paths, normalize_target_url, resolve_scan_options


def test_normalize_target_url_adds_https() -> None:
    assert normalize_target_url("example.com") == "https://example.com"
    assert normalize_target_url("http://example.com") == "http://example.com"


def test_resolve_scan_options_profile_and_overrides() -> None:
    timeout, max_requests, depth = resolve_scan_options("deep", None, None, None)
    assert (timeout, max_requests, depth) == (45, 450, 2)

    timeout, max_requests, depth = resolve_scan_options("deep", 10, 50, 0)
    assert (timeout, max_requests, depth) == (10, 50, 0)


def test_build_auto_report_paths_uses_target_and_extensions() -> None:
    json_path, md_path = build_auto_report_paths("https://example.com", Path("reports"))
    assert json_path.suffix == ".json"
    assert md_path is not None and md_path.suffix == ".md"
    assert "example.com_" in json_path.name
