
"""HTTP header privacy checks."""

from __future__ import annotations

from privacyintent.models import Finding, ScanArtifacts

REQUIRED_HEADERS = {
    "referrer-policy": {"strict-origin-when-cross-origin", "strict-origin", "no-referrer"},
    "permissions-policy": set(),
    "content-security-policy": set(),
    "x-content-type-options": {"nosniff"},
}


def detect(artifacts: ScanArtifacts) -> list[Finding]:
    findings: list[Finding] = []
    if not artifacts.headers:
        return findings

    # Prefer the root response headers if present.
    selected = artifacts.headers[0]
    for snap in artifacts.headers:
        if snap.url == artifacts.root_url:
            selected = snap
            break
    header_map = {k.lower(): v for k, v in selected.headers.items()}

    for idx, (header_name, recommended_values) in enumerate(REQUIRED_HEADERS.items(), start=1):
        value = header_map.get(header_name)
        if value is None:
            findings.append(
                Finding(
                    id=f"headers-{idx}",
                    severity="high" if header_name in {"content-security-policy", "permissions-policy"} else "medium",
                    category="headers",
                    description=f"Missing {header_name} header.",
                    evidence={"header": header_name, "url": selected.url},
                    recommendation=f"Set a strict {header_name} value for all HTML responses.",
                    confidence="high",
                )
            )
            continue

        if recommended_values and value.strip().lower() not in recommended_values:
            findings.append(
                Finding(
                    id=f"headers-{idx}-weak",
                    severity="medium",
                    category="headers",
                    description=f"Weak {header_name} value.",
                    evidence={"header": header_name, "value": value, "url": selected.url},
                    recommendation=f"Use one of: {', '.join(sorted(recommended_values))}.",
                    confidence="med",
                )
            )
    return findings
