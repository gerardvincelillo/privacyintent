
"""Third-party request detection."""

from __future__ import annotations

from urllib.parse import urlparse

import tldextract

from privacyintent.models import Finding, ScanArtifacts


def _registered_domain(url: str) -> str:
    host = urlparse(url).hostname or ""
    ext = tldextract.extract(host)
    return ext.registered_domain.lower()


def detect(artifacts: ScanArtifacts) -> list[Finding]:
    findings: list[Finding] = []
    first_party = _registered_domain(artifacts.root_url)

    for idx, req in enumerate(artifacts.requests, start=1):
        request_domain = _registered_domain(req.url)
        if not request_domain or not first_party or request_domain == first_party:
            continue
        findings.append(
            Finding(
                id=f"third-party-{idx}",
                severity="medium",
                category="third_party",
                description="Request sent to a third-party domain.",
                evidence={"url": req.url, "domain": request_domain, "first_party": first_party},
                recommendation="Minimize third-party dependencies and review vendor data sharing.",
                confidence="high",
            )
        )
    return findings
