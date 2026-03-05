
"""PII leak detection heuristics."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from privacy_intent.models import Finding, ScanArtifacts

PII_KEYWORDS = {
    "email",
    "phone",
    "name",
    "address",
    "token",
    "session",
    "auth",
    "password",
    "ssn",
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\-\s()]{7,}\d")


def _matches_pii(value: str) -> bool:
    return bool(EMAIL_RE.search(value) or PHONE_RE.search(value))


def detect(artifacts: ScanArtifacts) -> list[Finding]:
    findings: list[Finding] = []
    counter = 1

    for req in artifacts.requests:
        parsed = urlparse(req.url)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            key_l = key.lower()
            value_l = value.lower()
            if key_l in PII_KEYWORDS or any(word in key_l for word in PII_KEYWORDS) or _matches_pii(value):
                findings.append(
                    Finding(
                        id=f"pii-{counter}",
                        severity="high",
                        category="pii",
                        description="Potential PII found in request query parameters.",
                        evidence={"url": req.url, "parameter": key, "value": value},
                        recommendation="Remove or hash sensitive parameters before transmission.",
                        confidence="med" if _matches_pii(value) else "low",
                    )
                )
                counter += 1

        for header_name, header_value in req.headers.items():
            lower_name = header_name.lower()
            if lower_name in {"authorization", "cookie", "referer"}:
                findings.append(
                    Finding(
                        id=f"pii-{counter}",
                        severity="medium",
                        category="pii",
                        description="Sensitive header transmitted in request.",
                        evidence={"url": req.url, "header": header_name, "value": header_value},
                        recommendation="Avoid forwarding sensitive headers to third-party endpoints.",
                        confidence="med",
                    )
                )
                counter += 1
                continue
            if any(token in lower_name for token in PII_KEYWORDS) or any(token in header_value.lower() for token in PII_KEYWORDS):
                findings.append(
                    Finding(
                        id=f"pii-{counter}",
                        severity="medium",
                        category="pii",
                        description="Potential PII marker found in custom header.",
                        evidence={"url": req.url, "header": header_name, "value": header_value},
                        recommendation="Review custom headers for personal data leakage.",
                        confidence="low",
                    )
                )
                counter += 1

    return findings

