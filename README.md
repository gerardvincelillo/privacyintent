# PrivacyIntent

PrivacyIntent is an open-source CLI that audits websites for privacy leaks, tracker exposure, and risky data handling patterns.

## What It Does

- Launches a browser with Playwright and captures request/response traffic.
- Collects cookie metadata and response headers.
- Detects:
  - Third-party request flows
  - Weak cookie attributes
  - Missing/weak privacy headers
  - Potential PII leaks in query params and headers
  - Common tracker endpoints/scripts with confidence scoring
- Computes a privacy score (0-100) and highlights top risks.
- Outputs Rich console summary plus optional JSON and Markdown reports.

## Install

### pipx

```bash
pipx install privacyintent
python -m playwright install chromium
```

### pip

```bash
pip install privacyintent
python -m playwright install chromium
```

## Usage

```bash
privacyintent scan https://example.com
privacyintent scan https://example.com --json reports/example.json --md reports/example.md
privacyintent scan https://example.com --timeout 45 --max-requests 300 --depth 1 --no-headless
```

## Sample Output

```text
PrivacyIntent Summary
Target: https://example.com
Requests: 18
Cookies: 2
Findings: 6
Privacy Score: 71/100

Top Risks
- [HIGH] pii: Potential PII found in request query parameters.
- [HIGH] headers: Missing content-security-policy header.
- [MEDIUM] third_party: Request sent to a third-party domain.
```

## Architecture (Text Diagram)

```text
CLI (Typer)
  -> scanner.py (Playwright capture + crawl)
    -> detectors/
       - third_party
       - cookies
       - headers
       - pii
       - trackers
    -> scoring/privacy_score.py
    -> plugins/loader.py (optional entrypoint extensions)
    -> reporting/
       - console (Rich)
       - json_report
       - markdown_report
```

## Plugin Hooks

PrivacyIntent can discover optional extensions through Python entrypoints:

- Group: `privacyintent.plugins`
- Contract: callable accepting `ScanReport` and returning a list of additional findings
- Behavior: optional and failure-tolerant (graceful skip)

## Roadmap

- Pro plugin integration for CI/CD privacy gates (planned)
- Scheduled monitoring with drift/change detection (planned)
- Policy-as-code enforcement via YAML (planned)
- Compliance-oriented PDF reports (planned)
- Enterprise licensing and key management (planned)

## License

MIT
