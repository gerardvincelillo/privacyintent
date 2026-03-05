"""Scanning orchestrator."""

from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

from playwright.sync_api import BrowserContext, Response, sync_playwright

from privacy_intent.detectors import cookies, headers, pii, third_party, trackers
from privacy_intent.models import CookieRecord, HeaderSnapshot, RequestRecord, ResponseRecord, ScanArtifacts, ScanReport
from privacy_intent.plugins.loader import apply_plugins
from privacy_intent.reporting.console import print_summary
from privacy_intent.reporting.json_report import write_report as write_json_report
from privacy_intent.reporting.markdown_report import write_report as write_markdown_report
from privacy_intent.scoring.privacy_score import apply_privacy_score


def _normalize_headers(headers: dict[str, str] | None) -> dict[str, str]:
    if not headers:
        return {}
    return {str(k).lower(): str(v) for k, v in headers.items()}


def _same_origin(a: str, b: str) -> bool:
    pa = urlparse(a)
    pb = urlparse(b)
    return pa.scheme == pb.scheme and pa.netloc == pb.netloc


def _collect_links_from_page(page_url: str, links: list[str]) -> list[str]:
    normalized: list[str] = []
    for raw in links:
        if not raw:
            continue
        abs_url = urljoin(page_url, raw)
        parsed = urlparse(abs_url)
        if parsed.scheme in {"http", "https"}:
            normalized.append(abs_url)
    return normalized


def _attach_network_listeners(context: BrowserContext, artifacts: ScanArtifacts, max_requests: int) -> None:
    def on_request(request) -> None:
        if len(artifacts.requests) >= max_requests:
            return
        artifacts.requests.append(
            RequestRecord(
                method=request.method,
                url=request.url,
                resource_type=request.resource_type,
                initiator=request.frame.url if request.frame else None,
                headers=_normalize_headers(request.headers),
                post_data=request.post_data,
            )
        )

    def on_response(response: Response) -> None:
        if len(artifacts.responses) >= max_requests:
            return
        headers = _normalize_headers(response.headers)
        artifacts.responses.append(
            ResponseRecord(
                url=response.url,
                status=response.status,
                headers=headers,
                content_type=headers.get("content-type"),
            )
        )
        artifacts.headers.append(HeaderSnapshot(url=response.url, headers=headers))

    context.on("request", on_request)
    context.on("response", on_response)


def scan_site(
    url: str,
    json_path: Optional[Path],
    md_path: Optional[Path],
    timeout: int,
    max_requests: int,
    headless: bool,
    user_agent: Optional[str],
    depth: int,
    print_console_output: bool = True,
) -> ScanReport:
    """Capture network artifacts from a target URL with optional shallow crawl."""
    artifacts = ScanArtifacts(root_url=url)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(user_agent=user_agent) if user_agent else browser.new_context()
        _attach_network_listeners(context, artifacts, max_requests)
        page = context.new_page()
        queue: deque[tuple[str, int]] = deque([(url, 0)])
        seen: set[str] = set()

        while queue:
            target_url, current_depth = queue.popleft()
            if target_url in seen:
                continue
            seen.add(target_url)
            artifacts.visited_urls.append(target_url)

            try:
                page.goto(target_url, wait_until="networkidle", timeout=timeout * 1000)
            except Exception:
                continue

            if current_depth >= depth:
                continue

            raw_links = page.eval_on_selector_all("a[href]", "nodes => nodes.map(n => n.getAttribute('href'))")
            for candidate in _collect_links_from_page(target_url, raw_links):
                if _same_origin(url, candidate) and candidate not in seen:
                    queue.append((candidate, current_depth + 1))

        for raw_cookie in context.cookies():
            artifacts.cookies.append(
                CookieRecord(
                    name=raw_cookie.get("name", ""),
                    domain=raw_cookie.get("domain", ""),
                    path=raw_cookie.get("path"),
                    secure=bool(raw_cookie.get("secure")),
                    http_only=bool(raw_cookie.get("httpOnly")),
                    same_site=raw_cookie.get("sameSite"),
                    expires=raw_cookie.get("expires"),
                )
            )

        browser.close()

    findings = []
    findings.extend(third_party.detect(artifacts))
    findings.extend(cookies.detect(artifacts))
    findings.extend(headers.detect(artifacts))
    findings.extend(pii.detect(artifacts))
    findings.extend(trackers.detect(artifacts))
    report = ScanReport(artifacts=artifacts, findings=findings)
    report.findings.extend(apply_plugins(report))
    report = apply_privacy_score(report)
    if print_console_output:
        print_summary(report)

    if json_path is not None:
        write_json_report(json_path, report)
    if md_path is not None:
        write_markdown_report(md_path, report)
    return report

