
"""Core data models for scan data and findings."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]
Category = Literal["cookies", "trackers", "headers", "pii", "third_party"]
Confidence = Literal["low", "med", "high"]


class RequestRecord(BaseModel):
    method: str
    url: str
    resource_type: str | None = None
    initiator: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    post_data: str | None = None


class ResponseRecord(BaseModel):
    url: str
    status: int
    headers: dict[str, str] = Field(default_factory=dict)
    content_type: str | None = None


class CookieRecord(BaseModel):
    name: str
    domain: str
    path: str | None = None
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    expires: float | int | None = None


class HeaderSnapshot(BaseModel):
    url: str
    headers: dict[str, str] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    severity: Severity
    category: Category
    description: str
    evidence: str | dict[str, Any]
    recommendation: str
    confidence: Confidence


class ScanArtifacts(BaseModel):
    root_url: str
    visited_urls: list[str] = Field(default_factory=list)
    requests: list[RequestRecord] = Field(default_factory=list)
    responses: list[ResponseRecord] = Field(default_factory=list)
    cookies: list[CookieRecord] = Field(default_factory=list)
    headers: list[HeaderSnapshot] = Field(default_factory=list)


class ScanReport(BaseModel):
    artifacts: ScanArtifacts
    findings: list[Finding] = Field(default_factory=list)
    score: int = 100
    top_risks: list[Finding] = Field(default_factory=list)
