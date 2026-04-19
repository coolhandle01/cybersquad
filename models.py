"""
models.py — Pydantic data models shared across the entire pipeline.

Each model represents a discrete artefact that agents pass to one another.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScopeType(StrEnum):
    URL = "url"
    WILDCARD = "wildcard"
    IP_ADDRESS = "ip_address"
    CIDR = "cidr"
    ANDROID = "android"
    IOS = "ios"
    OTHER = "other"


class SubmissionStatus(StrEnum):
    PENDING = "pending"
    SUBMITTED = "submitted"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    DUPLICATE = "duplicate"
    NOT_APPLICABLE = "not_applicable"
    INFORMATIVE = "informative"


# ---------------------------------------------------------------------------
# Programme selection (Scout → everyone)
# ---------------------------------------------------------------------------


class ScopeItem(BaseModel):
    """A single in-scope or out-of-scope asset."""

    asset_identifier: str
    asset_type: ScopeType
    eligible_for_bounty: bool = True
    instruction: str | None = None


class Programme(BaseModel):
    """A HackerOne bug bounty programme selected by the Programme Manager."""

    handle: str
    name: str
    url: str
    bounty_table: dict[Severity, int]
    in_scope: list[ScopeItem]
    out_of_scope: list[ScopeItem]
    allows_automated_scanning: bool
    priority_score: float = 0.0
    selected_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Recon (OSINT Analyst → Penetration Tester)
# ---------------------------------------------------------------------------


class Endpoint(BaseModel):
    """A discovered HTTP/S endpoint."""

    url: str
    status_code: int | None = None
    technologies: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)


class ReconResult(BaseModel):
    """Everything the OSINT Analyst found about a programme's attack surface."""

    programme: Programme
    subdomains: list[str] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    open_ports: dict[str, list[int]] = Field(default_factory=dict)
    technologies: list[str] = Field(default_factory=list)
    notes: str = ""
    completed_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Vulnerability findings (Penetration Tester → Vulnerability Researcher)
# ---------------------------------------------------------------------------


class RawFinding(BaseModel):
    """An unverified potential vulnerability from automated tooling."""

    title: str
    vuln_class: str
    target: str
    evidence: str
    tool: str
    severity_hint: Severity = Severity.MEDIUM


class VerifiedVulnerability(BaseModel):
    """A confirmed, in-scope vulnerability after Vulnerability Researcher triage."""

    title: str
    vuln_class: str
    target: str
    severity: Severity
    cvss_score: float
    cvss_vector: str
    description: str
    steps_to_reproduce: list[str]
    evidence: str
    impact: str
    remediation: str
    in_scope: bool = True
    confirmed_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Report (Technical Author → Disclosure Coordinator)
# ---------------------------------------------------------------------------


class DisclosureReport(BaseModel):
    """A complete, submission-ready vulnerability report in H1 format."""

    programme_handle: str
    title: str
    vulnerability: VerifiedVulnerability
    summary: str
    body_markdown: str
    weakness_id: int | None = None
    structured_scope_id: str | None = None
    impact_statement: str
    attachments: list[str] = Field(default_factory=list)
    authored_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Submission (Disclosure Coordinator)
# ---------------------------------------------------------------------------


class SubmissionResult(BaseModel):
    """Result of a HackerOne report submission."""

    report_id: str | None = None
    status: SubmissionStatus = SubmissionStatus.PENDING
    h1_url: str | None = None
    submitted_at: datetime | None = None
    error: str | None = None
