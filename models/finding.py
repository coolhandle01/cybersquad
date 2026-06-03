"""
models.finding - the vuln-pipeline data shapes (PT -> VR -> TA).

``RawFinding`` is the unverified output of an automated probe;
``VerifiedVulnerability`` is the post-triage shape the Technical Author
turns into a report; ``RawFindingSummary`` is the compact slice the VR's
List Raw Findings tool returns. All three carry a ``Severity`` (from
``models.nvd``).
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from models.nvd import CvssVector, Severity


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
    cvss_vector: CvssVector
    description: str
    steps_to_reproduce: list[str]
    evidence: str
    impact: str
    remediation: str
    in_scope: bool = True
    confirmed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RawFindingSummary(BaseModel):
    """Compact summary of one raw finding, returned by List Raw Findings."""

    index: int
    title: str
    vuln_class: str
    target: str
    severity_hint: Severity
    evidence_bytes: int
