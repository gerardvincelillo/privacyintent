# PrivacyIntent

PrivacyIntent is an open-source Python CLI for privacy-focused web reconnaissance.
It scans a target URL using a real browser, collects network and cookie evidence,
and reports privacy risks with severity, confidence, and remediation guidance.

## Status

- Repository: public (`privacyintent`)
- Maturity: `v0.1` baseline
- Scope: privacy signal collection + heuristic risk detection

## Core Capabilities

- Browser-driven scan execution with Playwright (Chromium)
- Network artifact capture:
  - requests
  - responses
  - response headers
  - cookie metadata
- Heuristic detectors:
  - third-party request classification (`tldextract`)
  - cookie security posture (`Secure`, `HttpOnly`, `SameSite`, expiration)
  - privacy/security response headers
  - potential PII leakage in query params and headers
  - tracker endpoint/script heuristics with confidence scoring
- Privacy score calculation (0-100)
- Top-risk summarization (highest severity findings)
- Report outputs:
  - Rich console summary
  - JSON export
  - Markdown export
- Optional plugin hooks via entrypoints (`privacyintent.plugins`)

## Installation

### Prerequisites

- Python 3.11+
- Chromium browser binary for Playwright

### Install From Source

```bash
git clone https://github.com/gerardvincelillo/privacy-intent.git
cd privacy-intent
python -m pip install -e .
python -m playwright install chromium
```

## Usage

```bash
privacyintent scan https://example.com
```

With reduced setup (profile + auto artifacts):

```bash
privacyintent scan example.com --profile deep --artifacts-dir reports
```

Initialize starter files (config, policy, artifacts dir):

```bash
privacyintent init --path .
```

With report exports:

```bash
privacyintent scan https://example.com --json reports/example.json --md reports/example.md
```

With advanced options:

```bash
privacyintent scan https://example.com \
  --timeout 45 \
  --max-requests 300 \
  --depth 1 \
  --no-headless \
  --user-agent "Mozilla/5.0 (PrivacyIntent Audit)"
```

## CLI Reference

- `privacyintent scan <url>`
- `privacyintent ci scan <url>`: Pro CI gate command (requires `privacy-intent-pro`)
- `privacyintent compare <baseline.json> <current.json>`: compare privacy drift between reports
- `privacyintent monitor diff --baseline <a> --current <b>`: evaluate privacy drift for automation
- `privacyintent init --path <dir>`: scaffold starter config/policy/artifacts
- `--json <path>`: write JSON report
- `--md <path>`: write Markdown report
- `--sarif <path>`: write SARIF report for code scanning integrations
- `--gate-json <path>`: write CI gate result JSON (CI command)
- `--timeout <sec>`: browser navigation timeout (default: `30`)
- `--max-requests <n>`: max captured requests (default: `200`)
- `--headless/--no-headless`: browser mode (default: `--headless`)
- `--user-agent <string>`: custom user-agent override
- `--depth <n>`: same-origin crawl depth (default: `0`)
- `--profile <quick|standard|deep>`: apply tuned scan defaults
- `--artifacts-dir <path>`: auto-generate scan artifacts (and CI gate JSON in CI mode)
- `--json-only`: when auto-generating artifacts, skip Markdown output
- `--quiet`: disable console summary output for scan automation

## Automation Examples

Fail pipeline on regression:

```bash
privacyintent monitor diff \
  --baseline reports/baseline.json \
  --current reports/current.json \
  --fail-on-regression
```

## Output Model

Each finding includes:

- `id`
- `severity` (`low|medium|high|critical`)
- `category` (`cookies|trackers|headers|pii|third_party`)
- `description`
- `evidence` (string or structured object)
- `recommendation`
- `confidence` (`low|med|high`)

## Architecture

```text
privacy_intent/cli.py
  -> privacy_intent/scanner.py
     -> detectors/
        - third_party.py
        - cookies.py
        - headers.py
        - pii.py
        - trackers.py
     -> scoring/privacy_score.py
     -> reporting/
        - console.py
        - json_report.py
        - markdown_report.py
     -> plugins/loader.py
```

## Plugin Extensions

PrivacyIntent supports optional extension discovery via Python entrypoints:

- Group: `privacyintent.plugins`
- Expected plugin contract: callable taking `ScanReport` and returning a list of additional findings
- Failure behavior: plugin load/runtime errors are ignored to keep base scanning reliable

## OSS vs Pro

PrivacyIntent Pro now exists as a separate private repository (`privacy-intent-pro`).

Open-source `privacyintent` stays focused on:

- core scanning engine
- transparent detectors
- developer-friendly local/CI usage
- extensible plugin surface

Pro capabilities (CI gates, monitoring, policy enforcement, compliance reporting)
are delivered in the private Pro extension repository.

## Roadmap (Open-Source)

- Improve crawl strategy and request deduplication
- Expand tracker intelligence sources and confidence scoring
- Add baseline snapshots and diffable JSON for regression workflows
- Add tests for detector edge cases and scoring consistency
- Improve false-positive controls and detector tuning flags

## Current Limitations

- Heuristic detections can produce false positives and should be reviewed manually.
- Crawl strategy is intentionally shallow in `v0.1` and not a full crawler.
- No built-in persistence layer yet for historical diff analysis.
- Pro-only enforcement workflows (gates/monitoring/policy/PDF) are not in this OSS repo.

## License

MIT. See [LICENSE](LICENSE).

## Docs

- `docs/README.md`: docs index for the repository
- `docs/IMPLEMENTATION-CHECKLIST.md`
- `docs/PROJECT-VISION.md`
- `docs/STACK-INVENTORY.md`
