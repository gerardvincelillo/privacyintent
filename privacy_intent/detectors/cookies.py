
"""Cookie security checks."""

from __future__ import annotations

from time import time

from privacy_intent.models import Finding, ScanArtifacts


def detect(artifacts: ScanArtifacts) -> list[Finding]:
    findings: list[Finding] = []
    now = time()
    for idx, cookie in enumerate(artifacts.cookies, start=1):
        weaknesses: list[str] = []
        if not cookie.secure:
            weaknesses.append("missing Secure")
        if not cookie.http_only:
            weaknesses.append("missing HttpOnly")
        if (cookie.same_site or "").lower() in {"", "none"} and not cookie.secure:
            weaknesses.append("weak SameSite")
        if cookie.expires is None or (isinstance(cookie.expires, (int, float)) and cookie.expires > now + (365 * 24 * 3600)):
            weaknesses.append("unsafe expiration")

        if not weaknesses:
            continue

        severity = "high" if "missing Secure" in weaknesses else "medium"
        findings.append(
            Finding(
                id=f"cookie-{idx}",
                severity=severity,
                category="cookies",
                description=f"Cookie {cookie.name} has weak security attributes.",
                evidence={
                    "cookie": cookie.name,
                    "domain": cookie.domain,
                    "weaknesses": weaknesses,
                },
                recommendation="Set Secure, HttpOnly, strict SameSite, and bounded expiration.",
                confidence="high",
            )
        )
    return findings

