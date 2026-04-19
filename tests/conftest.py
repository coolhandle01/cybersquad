"""
tests/conftest.py — shared fixtures for the Bounty Squad test suite.
"""

from __future__ import annotations

import pytest

from models import (
    DisclosureReport,
    Endpoint,
    Programme,
    RawFinding,
    ReconResult,
    ScopeItem,
    ScopeType,
    Severity,
    VerifiedVulnerability,
)

# ── Programme fixtures ────────────────────────────────────────────────────────


@pytest.fixture()
def scope_item_url() -> ScopeItem:
    return ScopeItem(
        asset_identifier="https://example.com",
        asset_type=ScopeType.URL,
        eligible_for_bounty=True,
    )


@pytest.fixture()
def scope_item_wildcard() -> ScopeItem:
    return ScopeItem(
        asset_identifier="*.example.com",
        asset_type=ScopeType.WILDCARD,
        eligible_for_bounty=True,
    )


@pytest.fixture()
def programme(scope_item_url, scope_item_wildcard) -> Programme:
    return Programme(
        handle="test-programme",
        name="Test Programme",
        url="https://hackerone.com/test-programme",
        bounty_table={
            Severity.LOW: 100,
            Severity.MEDIUM: 500,
            Severity.HIGH: 2000,
            Severity.CRITICAL: 5000,
        },
        in_scope=[scope_item_url, scope_item_wildcard],
        out_of_scope=[],
        allows_automated_scanning=True,
    )


# ── Recon fixtures ────────────────────────────────────────────────────────────


@pytest.fixture()
def endpoint() -> Endpoint:
    return Endpoint(
        url="https://api.example.com",
        status_code=200,
        technologies=["nginx", "React"],
        parameters=["q", "page"],
    )


@pytest.fixture()
def recon_result(programme, endpoint) -> ReconResult:
    return ReconResult(
        programme=programme,
        subdomains=["api.example.com", "admin.example.com"],
        endpoints=[endpoint],
        open_ports={"api.example.com": [80, 443]},
        technologies=["nginx", "React"],
        notes="Test recon result.",
    )


# ── Vulnerability fixtures ────────────────────────────────────────────────────


@pytest.fixture()
def raw_finding_high() -> RawFinding:
    return RawFinding(
        title="SQL Injection — https://api.example.com/search",
        vuln_class="SQLi",
        target="https://api.example.com/search",
        evidence="sqlmap identified injection at parameter 'q'",
        tool="sqlmap",
        severity_hint=Severity.HIGH,
    )


@pytest.fixture()
def raw_finding_low() -> RawFinding:
    return RawFinding(
        title="Missing X-Frame-Options",
        vuln_class="Headers",
        target="https://api.example.com",
        evidence="X-Frame-Options header absent",
        tool="nuclei",
        severity_hint=Severity.LOW,
    )


@pytest.fixture()
def raw_finding_oos() -> RawFinding:
    """A finding whose target is outside programme scope."""
    return RawFinding(
        title="XSS — https://other.com/search",
        vuln_class="XSS",
        target="https://other.com/search",
        evidence="<script>alert(1)</script> reflected",
        tool="nuclei",
        severity_hint=Severity.HIGH,
    )


@pytest.fixture()
def verified_vuln() -> VerifiedVulnerability:
    return VerifiedVulnerability(
        title="SQL Injection — https://api.example.com/search",
        vuln_class="SQLi",
        target="https://api.example.com/search",
        severity=Severity.HIGH,
        cvss_score=8.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        description="A SQL injection vulnerability exists at the search endpoint.",
        steps_to_reproduce=[
            "Navigate to https://api.example.com/search?q=test",
            "Append a single quote to the q parameter",
            "Observe database error in the response",
        ],
        evidence="sqlmap identified injection at parameter 'q'",
        impact="An attacker can exfiltrate the entire database.",
        remediation="Use parameterised queries. See OWASP SQL Injection Prevention Cheat Sheet.",
    )


@pytest.fixture()
def disclosure_report(verified_vuln) -> DisclosureReport:
    return DisclosureReport(
        programme_handle="test-programme",
        title=verified_vuln.title,
        vulnerability=verified_vuln,
        summary="A SQL injection vulnerability at the search endpoint allows full DB exfiltration.",
        body_markdown="# SQL Injection\n\n## Summary\n\nTest report body.",
        weakness_id=89,
        impact_statement=verified_vuln.impact,
    )
