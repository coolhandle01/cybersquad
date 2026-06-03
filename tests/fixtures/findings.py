"""Finding / vulnerability / disclosure / attack-plan fixtures.

The ``raw_finding_*`` set covers the three tiers the triage gate
discriminates against (high in-scope, low in-scope, out-of-scope);
``verified_vuln`` -> ``disclosure_report`` walks the post-triage
chain; ``attack_tree`` / ``attack_forest`` are the VR research
artefact the PT consumes.

Loaded via ``pytest_plugins`` in ``tests/conftest.py``.
"""

from __future__ import annotations

import pytest

from models import RawFinding, Severity, VerifiedVulnerability
from models.attack import AttackForest, AttackTree
from models.h1 import DisclosureReport


def _wrap_authored(authored: dict[str, object], **overrides: object) -> dict[str, object]:
    """Wrap an authored payload as ``{finding_index, authored}`` and apply
    ``overrides`` - a key that names an authored field mutates it, any other
    key (``finding_index`` / ``verified_path``) sets a top-level field."""
    base: dict[str, object] = {"finding_index": 0, "authored": authored}
    for key, value in overrides.items():
        if key in authored:
            authored[key] = value
        else:
            base[key] = value
    return base


def authored_draft(**overrides: object) -> dict[str, object]:
    """The canonical ``AuthoredDraft`` inner shape (the agent-authored half of a
    report draft). Pass overrides to mutate a field. Use this when a test pokes
    the authored payload directly; for the full Draft-tool kwargs (wrapped under
    ``authored`` with ``finding_index``) use ``draft_report_kwargs``."""
    authored: dict[str, object] = {
        "title": "SQL Injection in /search?q allows full database extraction",
        "summary": (
            "The /search endpoint concatenates user input into a SELECT statement. "
            "An unauthenticated attacker can dump the entire users table."
        ),
        "description": (
            "The handler concatenates the q parameter directly into the SQL statement "
            "with no parameterisation. Standard UNION-based injection extracts arbitrary "
            "rows from the users table."
        ),
        "steps_to_reproduce": [
            "Issue GET /search?q=test' UNION SELECT 1,2,3-- ",
            "Observe the response body contains the union'd rows.",
        ],
        "evidence": 'HTTP/1.1 200 OK\n\n[{"username":"alice"}]',
        "impact": (
            "An unauthenticated attacker can dump the entire users table including bcrypt "
            "hashes and email addresses, enabling offline cracking and full account takeover."
        ),
        "remediation": (
            "Use parameterised queries throughout the ORM. See "
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": 89,
    }
    authored.update(overrides)
    return authored


def draft_report_kwargs(**overrides: object) -> dict[str, object]:
    """Canonical kwargs for the Technical Author's Draft Vulnerability Report
    tool / ``_DraftReportArgs``: ``authored_draft`` wrapped under ``authored``
    with ``finding_index``. An override naming an authored field mutates it; any
    other key (``finding_index`` / ``verified_path``) sets a top-level field.
    The shared source for both the tool-test and the args-schema-test (was
    duplicated as ``_good_authoring`` / ``_good_authored_draft``)."""
    return _wrap_authored(authored_draft(), **overrides)


def authored_assessment(**overrides: object) -> dict[str, object]:
    """The canonical ``AuthoredAssessment`` inner shape (the VR's triage call).
    Pass overrides to mutate a field; for the full Assess-tool kwargs use
    ``assess_finding_kwargs``."""
    authored: dict[str, object] = {
        "severity_decision": "keep",
        "severity": "high",
        "severity_rationale": (
            "Unauthenticated SQLi at a public endpoint with full DB read available - "
            "matches the PT high call."
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "title": "SQL Injection in /search?q allows database extraction",
        "description": (
            "The /search endpoint concatenates q into a SELECT statement without "
            "parameterisation. sqlmap exploits classic UNION-based injection to extract "
            "rows from the users table."
        ),
        "steps_to_reproduce": [
            "Issue GET /search?q=test' UNION SELECT 1,2,3-- ",
            "Observe the response body contains the union'd rows.",
        ],
        "impact": (
            "An authenticated attacker dumps the users table including bcrypt hashes and "
            "emails, enabling offline cracking and account takeover."
        ),
        "remediation": (
            "Use parameterised queries throughout. See "
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ),
    }
    authored.update(overrides)
    return authored


def assess_finding_kwargs(**overrides: object) -> dict[str, object]:
    """Canonical kwargs for the Vulnerability Researcher's Assess Raw Finding
    tool / ``_AssessRawFindingArgs``: ``authored_assessment`` wrapped under
    ``authored`` with ``finding_index``. Same override / wrapping contract as
    ``draft_report_kwargs`` (was duplicated as ``_good_authoring`` /
    ``_good_authored_kwargs``)."""
    return _wrap_authored(authored_assessment(), **overrides)


@pytest.fixture()
def raw_finding_high(target_apex: str) -> RawFinding:
    return RawFinding(
        title=f"SQL Injection - https://api.{target_apex}/search",
        vuln_class="SQLi",
        target=f"https://api.{target_apex}/search",
        evidence="sqlmap identified injection at parameter 'q'",
        tool="sqlmap",
        severity_hint=Severity.HIGH,
    )


@pytest.fixture()
def raw_finding_low(target_apex: str) -> RawFinding:
    return RawFinding(
        title="Missing X-Frame-Options",
        vuln_class="Headers",
        target=f"https://api.{target_apex}",
        evidence="X-Frame-Options header absent",
        tool="nuclei",
        severity_hint=Severity.LOW,
    )


@pytest.fixture()
def raw_finding_oos() -> RawFinding:
    """A finding whose target is outside programme scope."""
    return RawFinding(
        title="XSS - https://other.com/search",
        vuln_class="XSS",
        target="https://other.com/search",
        evidence="<script>alert(1)</script> reflected",
        tool="nuclei",
        severity_hint=Severity.HIGH,
    )


@pytest.fixture()
def verified_vuln(target_apex: str) -> VerifiedVulnerability:
    return VerifiedVulnerability(
        title=f"SQL Injection - https://api.{target_apex}/search",
        vuln_class="SQLi",
        target=f"https://api.{target_apex}/search",
        severity=Severity.HIGH,
        cvss_score=8.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        description="A SQL injection vulnerability exists at the search endpoint.",
        steps_to_reproduce=[
            f"Navigate to https://api.{target_apex}/search?q=test",
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


@pytest.fixture()
def attack_tree(target_apex: str) -> AttackTree:
    return AttackTree(
        probe="CVE-2022-22965",
        target=f"https://api.{target_apex}",
        expected_ceiling=Severity.CRITICAL,
        rationale=(
            "Tomcat-served Spring Boot 2.3 detected in recon; test the standard "
            "POST payload and look for arbitrary file write in the webroot."
        ),
        recon_evidence=[
            f"api.{target_apex} runs Tomcat 9.0",
            "Spring Boot 2.3 banner observed on /actuator/info",
        ],
    )


@pytest.fixture()
def attack_forest(attack_tree) -> AttackForest:
    from datetime import UTC, datetime

    return AttackForest(
        programme_handle="test-programme",
        drafted_at=datetime(2026, 1, 1, tzinfo=UTC),
        trees=[attack_tree],
    )
