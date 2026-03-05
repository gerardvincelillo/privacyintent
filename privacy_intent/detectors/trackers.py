
"""Tracker endpoint detection heuristics."""

from __future__ import annotations

from privacy_intent.models import Finding, ScanArtifacts

TRACKER_SUBSTRINGS = [
    "analytics",
    "tag",
    "pixel",
    "collect",
    "gtm",
    "segment",
    "mixpanel",
    "amplitude",
    "facebook.com/tr",
    "google-analytics",
]

KNOWN_ENDPOINTS = [
    "https://www.google-analytics.com/g/collect",
    "https://www.googletagmanager.com/gtm.js",
    "https://connect.facebook.net/en_US/fbevents.js",
]


def _confidence_for_url(url: str) -> str:
    lower = url.lower()
    if lower in (endpoint.lower() for endpoint in KNOWN_ENDPOINTS):
        return "high"
    if sum(token in lower for token in TRACKER_SUBSTRINGS) >= 2:
        return "high"
    return "med"


def detect(artifacts: ScanArtifacts) -> list[Finding]:
    findings: list[Finding] = []
    counter = 1
    for req in artifacts.requests:
        lower = req.url.lower()
        if not any(token in lower for token in TRACKER_SUBSTRINGS):
            continue
        confidence = _confidence_for_url(req.url)
        severity = "high" if confidence == "high" else "medium"
        findings.append(
            Finding(
                id=f"tracker-{counter}",
                severity=severity,
                category="trackers",
                description="Potential tracker request detected.",
                evidence={"url": req.url, "resource_type": req.resource_type},
                recommendation="Review tracker necessity and gate with explicit user consent.",
                confidence=confidence,
            )
        )
        counter += 1
    return findings

