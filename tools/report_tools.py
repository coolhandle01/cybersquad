"""
tools/report_tools.py — Report generation for the Technical Author agent.

Produces structured, professional H1-compatible Markdown reports from
verified vulnerabilities.
"""

from __future__ import annotations

import textwrap
from datetime import datetime
from pathlib import Path

from config import config
from models import DisclosureReport, Severity, VerifiedVulnerability

# ---------------------------------------------------------------------------
# CWE quick-reference
# ---------------------------------------------------------------------------

_VULN_CLASS_TO_CWE: dict[str, int] = {
    "SQLi": 89,
    "XSS": 79,
    "IDOR": 639,
    "SSRF": 918,
    "CORS": 942,
    "RCE": 78,
    "LFI": 22,
    "XXE": 611,
    "SSTI": 94,
    "CSRF": 352,
    "AuthZ": 285,
    "AuthN": 287,
    "OpenRedirect": 601,
}

_SEVERITY_LABELS: dict[Severity, str] = {
    Severity.INFORMATIONAL: "None",
    Severity.LOW: "Low",
    Severity.MEDIUM: "Medium",
    Severity.HIGH: "High",
    Severity.CRITICAL: "Critical",
}

_REPORT_TEMPLATE = """\
# {title}

## Summary

{summary}

---

## Vulnerability Details

| Field | Value |
|---|---|
| **Type** | {vuln_class} |
| **Severity** | {severity} |
| **CVSS Score** | {cvss_score} |
| **CVSS Vector** | `{cvss_vector}` |
| **CWE** | CWE-{cwe} |
| **Target** | `{target}` |

---

## Description

{description}

---

## Steps to Reproduce

{steps}

---

## Evidence

```
{evidence}
```

---

## Impact

{impact}

---

## Remediation

{remediation}

---

*Report generated {timestamp} by Bounty Squad.*
"""


def _format_steps(steps: list[str]) -> str:
    return "\n".join(f"{i + 1}. {step}" for i, step in enumerate(steps))


def build_report_markdown(
    programme_handle: str,
    vulnerability: VerifiedVulnerability,
    summary: str,
) -> str:
    """Render the Markdown body of a disclosure report."""
    cwe = _VULN_CLASS_TO_CWE.get(vulnerability.vuln_class, 0)

    return _REPORT_TEMPLATE.format(
        title=vulnerability.title,
        summary=summary,
        vuln_class=vulnerability.vuln_class,
        severity=_SEVERITY_LABELS[vulnerability.severity],
        cvss_score=vulnerability.cvss_score,
        cvss_vector=vulnerability.cvss_vector,
        cwe=cwe if cwe else "N/A",
        target=vulnerability.target,
        description=vulnerability.description,
        steps=_format_steps(vulnerability.steps_to_reproduce),
        evidence=textwrap.indent(vulnerability.evidence[:2000], "  "),
        impact=vulnerability.impact,
        remediation=vulnerability.remediation,
        timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    )


def create_disclosure_report(
    programme_handle: str,
    vulnerability: VerifiedVulnerability,
    summary: str,
) -> DisclosureReport:
    """Assemble a complete DisclosureReport ready for submission."""
    body_markdown = build_report_markdown(programme_handle, vulnerability, summary)
    cwe = _VULN_CLASS_TO_CWE.get(vulnerability.vuln_class)

    return DisclosureReport(
        programme_handle=programme_handle,
        title=vulnerability.title,
        vulnerability=vulnerability,
        summary=summary,
        body_markdown=body_markdown,
        weakness_id=cwe,
        impact_statement=vulnerability.impact,
    )


def save_report(report: DisclosureReport) -> Path:
    """Save a report to the configured reports directory. Returns the file path."""
    reports_dir = Path(config.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_title = report.title.replace(" ", "_").replace("/", "-")[:60]
    filename = reports_dir / f"{timestamp}_{report.programme_handle}_{safe_title}.md"

    filename.write_text(report.body_markdown, encoding="utf-8")
    return filename
