"""
tools/vuln_tools.py — Penetration testing and vulnerability research tooling.

Two layers:
  1. Penetration Tester  — automated scanning with nuclei, sqlmap, custom checks
  2. Vulnerability Researcher — triage, CVSS scoring, scope validation

External dependencies:
    nuclei   https://github.com/projectdiscovery/nuclei
    sqlmap   https://github.com/sqlmapproject/sqlmap
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess

from config import config
from models import (
    Endpoint,
    Programme,
    RawFinding,
    ReconResult,
    Severity,
    VerifiedVulnerability,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_NUCLEI_SEVERITY_MAP: dict[str, Severity] = {
    "info": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_SEVERITY_FLOOR_ORDER = [
    Severity.INFORMATIONAL,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def _above_floor(severity: Severity) -> bool:
    floor = Severity(config.scan.min_severity)
    return _SEVERITY_FLOOR_ORDER.index(severity) >= _SEVERITY_FLOOR_ORDER.index(floor)


def _require_binary(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise OSError(f"Required binary '{name}' not found in PATH.")
    return path


def _run(cmd: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


# ---------------------------------------------------------------------------
# Nuclei scanner
# ---------------------------------------------------------------------------


def run_nuclei(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Run nuclei against a list of endpoints using severity-filtered templates.
    Returns raw findings above the configured severity floor.
    """
    # FIX: check for empty targets before requiring the binary so the test
    # for empty input doesn't raise EnvironmentError on machines without nuclei
    targets = [ep.url for ep in endpoints if ep.url]
    if not targets:
        return []

    nuclei = _require_binary("nuclei")

    import os
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        targets_file = f.name

    try:
        result = _run(
            [
                nuclei,
                "-list",
                targets_file,
                "-t",
                config.scan.nuclei_templates_path,
                "-severity",
                config.scan.min_severity,
                "-json",
                "-silent",
                # FIX: was hardcoded "10" — now reads from config
                "-rate-limit",
                str(config.scan.nuclei_rate_limit),
            ],
            timeout=600,
        )
    finally:
        os.unlink(targets_file)

    findings: list[RawFinding] = []
    for line in result.stdout.splitlines():
        try:
            entry = json.loads(line)
            sev = _NUCLEI_SEVERITY_MAP.get(
                entry.get("info", {}).get("severity", "medium"),
                Severity.MEDIUM,
            )
            if not _above_floor(sev):
                continue
            findings.append(
                RawFinding(
                    title=entry.get("info", {}).get("name", "Unknown"),
                    vuln_class=entry.get("info", {}).get("tags", ["unknown"])[0],
                    target=entry.get("matched-at", entry.get("host", "")),
                    evidence=json.dumps(entry.get("extracted-results", entry.get("request", ""))),
                    tool="nuclei",
                    severity_hint=sev,
                )
            )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.debug("Skipping nuclei line: %s", exc)

    logger.info("nuclei found %d findings", len(findings))
    return findings


# ---------------------------------------------------------------------------
# SQLMap scanner
# ---------------------------------------------------------------------------


def run_sqlmap(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Run sqlmap against parameterised endpoints.
    Only attempts endpoints that have detected parameters.
    """
    sqlmap = _require_binary("sqlmap")
    findings: list[RawFinding] = []

    param_endpoints = [ep for ep in endpoints if ep.parameters]
    logger.info("sqlmap: testing %d parameterised endpoints", len(param_endpoints))

    for ep in param_endpoints:
        result = _run(
            [
                sqlmap,
                "-u",
                ep.url,
                "--batch",
                "--level",
                str(config.scan.sqlmap_level),
                "--risk",
                str(config.scan.sqlmap_risk),
                # FIX: was hardcoded "/tmp/sqlmap-output" — now reads from config
                "--output-dir",
                config.scan.sqlmap_output_dir,
                "--forms",
                "--crawl=1",
            ],
            timeout=120,
        )
        if "sqlmap identified the following injection point" in result.stdout:
            findings.append(
                RawFinding(
                    title=f"SQL Injection — {ep.url}",
                    vuln_class="SQLi",
                    target=ep.url,
                    evidence=result.stdout[-2000:],
                    tool="sqlmap",
                    severity_hint=Severity.HIGH,
                )
            )

    logger.info("sqlmap found %d findings", len(findings))
    return findings


# ---------------------------------------------------------------------------
# Custom checks
# ---------------------------------------------------------------------------


def check_cors_misconfiguration(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Simple CORS misconfiguration check — sends a crafted Origin header
    and inspects the Access-Control-Allow-Origin response header.
    """
    import time

    import requests

    findings: list[RawFinding] = []
    evil_origin = "https://evil.example.com"

    for ep in endpoints:
        try:
            resp = requests.get(
                ep.url,
                headers={"Origin": evil_origin},
                timeout=config.recon.http_timeout,
                allow_redirects=False,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao == evil_origin or acao == "*":
                sev = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                findings.append(
                    RawFinding(
                        title=f"CORS Misconfiguration — {ep.url}",
                        vuln_class="CORS",
                        target=ep.url,
                        evidence=(
                            f"Origin: {evil_origin}\n"
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac}"
                        ),
                        tool="custom_cors_check",
                        severity_hint=sev,
                    )
                )
            time.sleep(config.scan.request_delay)
        except Exception as exc:
            logger.debug("CORS check failed for %s: %s", ep.url, exc)

    logger.info("CORS check found %d findings", len(findings))
    return findings


# ---------------------------------------------------------------------------
# Penetration Tester orchestration
# ---------------------------------------------------------------------------


def run_pentest(recon: ReconResult) -> list[RawFinding]:
    """
    Run all scanning tools against the recon surface.
    Returns deduplicated raw findings sorted by severity.
    """
    all_findings: list[RawFinding] = []
    all_findings.extend(run_nuclei(recon.endpoints))
    all_findings.extend(run_sqlmap(recon.endpoints))
    all_findings.extend(check_cors_misconfiguration(recon.endpoints))

    all_findings.sort(
        key=lambda f: _SEVERITY_FLOOR_ORDER.index(f.severity_hint),
        reverse=True,
    )
    logger.info("Pentest complete — %d raw findings", len(all_findings))
    return all_findings


# ---------------------------------------------------------------------------
# Vulnerability Researcher — triage & CVSS
# ---------------------------------------------------------------------------

_CVSS_DEFAULTS: dict[str, dict[Severity, tuple[float, str]]] = {
    "SQLi": {
        Severity.CRITICAL: (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        Severity.HIGH: (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    },
    "XSS": {
        Severity.HIGH: (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
        Severity.MEDIUM: (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    },
    "CORS": {
        Severity.HIGH: (7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"),
        Severity.MEDIUM: (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    },
    "DEFAULT": {
        Severity.CRITICAL: (9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        Severity.HIGH: (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        Severity.MEDIUM: (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
        Severity.LOW: (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    },
}


def _lookup_cvss(vuln_class: str, severity: Severity) -> tuple[float, str]:
    table = _CVSS_DEFAULTS.get(vuln_class, _CVSS_DEFAULTS["DEFAULT"])
    if severity in table:
        return table[severity]
    return _CVSS_DEFAULTS["DEFAULT"].get(
        severity, (5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
    )


def is_in_scope(finding: RawFinding, programme: Programme) -> bool:
    """Check whether a finding's target falls within the programme scope."""
    from tools.recon_tools import extract_domain, filter_in_scope

    domain = extract_domain(finding.target)
    return bool(filter_in_scope([domain], programme))


def triage_findings(
    raw_findings: list[RawFinding],
    programme: Programme,
) -> list[VerifiedVulnerability]:
    """
    Vulnerability Researcher triage:
      - Drop out-of-scope findings
      - Drop below-floor severities
      - Assign CVSS scores
      - Build structured VerifiedVulnerability objects
    """
    verified: list[VerifiedVulnerability] = []

    for finding in raw_findings:
        if not is_in_scope(finding, programme):
            logger.info("Out of scope, skipping: %s", finding.target)
            continue
        if not _above_floor(finding.severity_hint):
            continue

        cvss_score, cvss_vector = _lookup_cvss(finding.vuln_class, finding.severity_hint)

        verified.append(
            VerifiedVulnerability(
                title=finding.title,
                vuln_class=finding.vuln_class,
                target=finding.target,
                severity=finding.severity_hint,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                description=f"Automated detection of {finding.vuln_class} at {finding.target}.",
                steps_to_reproduce=[
                    f"Navigate to {finding.target}",
                    "Observe the following evidence:",
                    finding.evidence,
                ],
                evidence=finding.evidence,
                impact=f"Potential {finding.vuln_class} impact — pending manual review.",
                remediation=f"Refer to OWASP guidance for {finding.vuln_class} remediation.",
            )
        )

    logger.info(
        "Triage complete — %d/%d findings verified",
        len(verified),
        len(raw_findings),
    )
    return verified
