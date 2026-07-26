"""
tools/report_tools.py - Report-authoring primitives for the Technical Author.

The TA's job is to turn a VerifiedVulnerability into an H1-format report that a
triager accepts on first read. The agent does the writing; this module provides
the supporting primitives:

* ``calculate_cvss_score(vector)`` - score a CVSS 3.x vector string (via the
  ``cvss`` library).
* ``sanitise_evidence(text)`` - redact credentials / cookies / auth headers /
  long base64 blobs from raw tool output so it is safe to inline in a report.
* ``ReportDraft`` - the working artefact the TA composes per finding.
* ``validate_draft(draft)`` - quality gate. Returns the issue list the TA fixes
  before finalising. Hard errors block ``finalise_drafts``; warnings are
  advisory.
* ``render_draft_markdown(draft)`` - render a draft into H1 markdown.
* ``save_draft(draft)`` / ``load_drafts()`` - persist drafts under
  ``<run_dir>/drafts/<idx:03d>.json`` so the TA can iterate one finding at a
  time.
* ``finalise_drafts(programme_handle, summary, expected_count)`` - validate all
  drafts strictly, build a ``DisclosureReport`` per draft, and write
  ``reports.json`` for the Disclosure Coordinator. Refuses on hard errors.
* ``save_report(report)`` - persist a finalised report to the configured
  reports directory (kept for Disclosure Coordinator compatibility).

CWE enrichment comes from the ``models.mitre.CWE`` type (the bundled MITRE
corpus) and OWASP cheat-sheet hints from ``tools/owasp_data.py``. The Technical
Author looks them up via the dedicated tools.
"""

from __future__ import annotations

import json
import re
import textwrap
from datetime import UTC, datetime
from pathlib import Path

from cvss import CVSS3
from cvss.exceptions import CVSS3Error
from pydantic import BaseModel, Field

import runtime
from config import config
from models import CWE, Severity, VerifiedVulnerability
from models.h1 import DisclosureReport

_SEVERITY_LABELS: dict[Severity, str] = {
    Severity.INFORMATIONAL: "None",
    Severity.LOW: "Low",
    Severity.MEDIUM: "Medium",
    Severity.HIGH: "High",
    Severity.CRITICAL: "Critical",
}

_DRAFTS_SUBDIR = "drafts"
_EVIDENCE_LIMIT = 2000

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
| **CWE** | CWE-{cwe} ({cwe_name}) |
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


# CVSS


def calculate_cvss_score(vector: str) -> float:
    """Compute the CVSS 3.x base score from a vector string.

    Delegates to the ``cvss`` library (the canonical RedHat implementation of
    the CVSS specification) rather than re-deriving the formula by hand.
    Returns a value in 0.0-10.0. Raises ``ValueError`` for an unparseable
    vector, an unknown metric value, a missing mandatory metric, or a non-3.x
    version - preserving the boundary contract the recompute call sites in
    ``report_tools`` / ``triage_tools`` rely on (they catch ``ValueError``).
    """
    try:
        return float(CVSS3(vector).base_score)
    except CVSS3Error as exc:
        raise ValueError(f"invalid CVSS vector {vector!r}: {exc}") from exc


# Evidence sanitisation


class SanitisationReport(BaseModel):
    """Result of sanitising one chunk of evidence."""

    sanitised: str
    redactions: list[dict] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


# Patterns are ordered so the most specific match wins. ``kind`` is the label
# echoed back to the TA so they understand what the redactor caught.
_REDACTION_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "authorization_header",
        re.compile(r"(?im)^\s*Authorization:\s*\S.*$"),
        "Authorization: <redacted>",
    ),
    (
        "cookie_header",
        re.compile(r"(?im)^\s*Cookie:\s*\S.*$"),
        "Cookie: <redacted>",
    ),
    (
        "set_cookie_header",
        re.compile(r"(?im)^\s*Set-Cookie:\s*\S.*$"),
        "Set-Cookie: <redacted>",
    ),
    (
        "bearer_token",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}"),
        "Bearer <redacted>",
    ),
    (
        "basic_auth",
        re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}"),
        "Basic <redacted>",
    ),
    (
        "jwt",
        # Three dot-separated base64-url segments, the first beginning ``eyJ``
        # (the base64 of ``{"``) which is the canonical JWT header start.
        re.compile(r"eyJ[A-Za-z0-9._\-]{10,}\.[A-Za-z0-9._\-]{10,}\.[A-Za-z0-9._\-]{8,}"),
        "<redacted-jwt>",
    ),
    (
        "secret_kv",
        # key=value pairs where the key smells secret. Anchor on word boundary
        # so we do not strip ``password_reset_url=...`` style tokens.
        re.compile(
            r"(?i)\b(password|passwd|secret|api[_-]?key|apikey|access[_-]?token|"
            r"refresh[_-]?token|private[_-]?key)\s*[=:]\s*([^\s,;&]+)"
        ),
        r"\1=<redacted>",
    ),
    (
        "aws_access_key",
        re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
        "<redacted-aws-key>",
    ),
]


def sanitise_evidence(text: str, limit: int = _EVIDENCE_LIMIT) -> SanitisationReport:
    """Redact credentials, tokens, cookies and other secret-shaped material
    from ``text`` and truncate to ``limit`` characters.

    Payloads (XSS strings, SQL injection vectors, SSRF URLs) are deliberately
    *not* touched - the disclosure is private and the triager needs the literal
    request that demonstrates the issue. Only material that would compromise
    the researcher (or another user) if published is stripped.
    """
    redactions: list[dict] = []
    warnings: list[str] = []
    sanitised = text or ""

    for kind, pattern, replacement in _REDACTION_PATTERNS:
        matches = pattern.findall(sanitised)
        if not matches:
            continue
        sample = ""
        for match in matches:
            sample = match if isinstance(match, str) else "".join(match)
            break
        redactions.append(
            {
                "kind": kind,
                "count": len(matches),
                "sample": sample[:60],
            }
        )
        sanitised = pattern.sub(replacement, sanitised)

    if len(sanitised) > limit:
        original_len = len(sanitised)
        sanitised = sanitised[:limit].rstrip() + "\n... [truncated]"
        warnings.append(
            f"evidence truncated from {original_len} to {limit} chars; "
            "keep the most diagnostic excerpt"
        )

    return SanitisationReport(sanitised=sanitised, redactions=redactions, warnings=warnings)


# Draft model


class ReportDraft(BaseModel):
    """One Technical-Author-composed report draft.

    Only the fields a triager actually reads. CVSS, CWE, target, vuln_class,
    and severity come from the verified finding (so the TA cannot accidentally
    contradict the VR); the prose lives here, owned by the TA.
    """

    # Carried from verified.json
    finding_index: int
    target: str
    vuln_class: str
    severity: Severity
    cvss_vector: str
    cvss_score: float
    cwe_id: int

    # Authored
    title: str
    summary: str
    description: str
    steps_to_reproduce: list[str]
    evidence: str
    impact: str
    remediation: str

    authored_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# Validation


_TITLE_FORMULA = re.compile(r".+\s+in\s+.+\s+allows\s+.+", re.IGNORECASE)
_HAND_WAVY_IMPACT = re.compile(
    r"\b(could compromise|may allow|might allow|potentially|possibly|"
    r"can lead to(?! \w)|attacker could|impact unknown)\b",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://\S+")
_SENTENCE_END = re.compile(r"[.!?]+\s+")


class ValidationIssue(BaseModel):
    """A single quality finding from validate_draft."""

    section: str
    severity: str  # "error" (blocks finalise) or "warning" (advisory)
    message: str


class ValidationReport(BaseModel):
    """Result of validating one draft."""

    ok: bool
    issues: list[ValidationIssue] = Field(default_factory=list)


class ReportDraftResult(BaseModel):
    """Return shape of the Draft Vulnerability Report tool.

    ``path`` is the workspace-relative location of the persisted draft
    (e.g. ``drafts/000.json``); ``validation`` is the quality-gate report
    for the draft that was just authored.
    """

    path: str
    validation: ValidationReport


def _count_sentences(text: str) -> int:
    text = text.strip()
    if not text:
        return 0
    chunks = [c for c in _SENTENCE_END.split(text) if c.strip()]
    return max(1, len(chunks))


def validate_draft(draft: ReportDraft) -> ValidationReport:
    """Apply quality heuristics to a draft. Returns the issue list."""
    issues: list[ValidationIssue] = []

    # Title
    if not draft.title.strip():
        issues.append(ValidationIssue(section="title", severity="error", message="title is empty"))
    else:
        if not _TITLE_FORMULA.match(draft.title.strip()):
            issues.append(
                ValidationIssue(
                    section="title",
                    severity="error",
                    message=(
                        "title does not match `[Type] in [Component] allows [Outcome]`; "
                        f"got: {draft.title!r}"
                    ),
                )
            )
        if len(draft.title) > 120:
            issues.append(
                ValidationIssue(
                    section="title",
                    severity="warning",
                    message=f"title is {len(draft.title)} chars; aim for under 120",
                )
            )

    # Summary
    sentences = _count_sentences(draft.summary)
    if sentences < 2:
        issues.append(
            ValidationIssue(
                section="summary",
                severity="error",
                message="summary should be 2-3 sentences covering root cause, location, impact",
            )
        )
    elif sentences > 5:
        issues.append(
            ValidationIssue(
                section="summary",
                severity="warning",
                message=f"summary is {sentences} sentences; aim for 2-3",
            )
        )

    # Description
    if len(draft.description.strip()) < 100:
        issues.append(
            ValidationIssue(
                section="description",
                severity="error",
                message=(
                    "description is too thin; explain root cause to a developer "
                    "(why the code is vulnerable, not just what happens)"
                ),
            )
        )

    # Steps
    if len(draft.steps_to_reproduce) < 2:
        issues.append(
            ValidationIssue(
                section="steps_to_reproduce",
                severity="error",
                message="at least 2 numbered steps are required",
            )
        )
    for n, step in enumerate(draft.steps_to_reproduce, 1):
        if len(step.strip()) < 10:
            issues.append(
                ValidationIssue(
                    section="steps_to_reproduce",
                    severity="error",
                    message=f"step {n} is too short to be reproducible: {step!r}",
                )
            )

    # Evidence
    if not draft.evidence.strip():
        issues.append(
            ValidationIssue(
                section="evidence",
                severity="error",
                message="evidence is empty; include the captured request/response or tool output",
            )
        )
    else:
        residual = sanitise_evidence(draft.evidence)
        if residual.redactions:
            kinds = ", ".join(sorted({r["kind"] for r in residual.redactions}))
            issues.append(
                ValidationIssue(
                    section="evidence",
                    severity="error",
                    message=(
                        f"evidence still contains sensitive material ({kinds}); "
                        "call Sanitise Evidence first and inline the sanitised result"
                    ),
                )
            )

    # Impact
    if len(draft.impact.strip()) < 40:
        issues.append(
            ValidationIssue(
                section="impact",
                severity="error",
                message=(
                    "impact statement too short; name the data/system at risk, "
                    "who is affected, and the realistic worst outcome"
                ),
            )
        )
    if _HAND_WAVY_IMPACT.search(draft.impact):
        issues.append(
            ValidationIssue(
                section="impact",
                severity="error",
                message=(
                    "impact statement uses hand-wavy language (e.g. 'could compromise', "
                    "'may allow'); be concrete about what an attacker can actually do"
                ),
            )
        )

    # Remediation
    if len(draft.remediation.strip()) < 60:
        issues.append(
            ValidationIssue(
                section="remediation",
                severity="error",
                message="remediation too thin; give the developer a concrete fix",
            )
        )
    if not _URL.search(draft.remediation):
        issues.append(
            ValidationIssue(
                section="remediation",
                severity="error",
                message=(
                    "remediation must cite an OWASP cheat-sheet or CWE URL; "
                    "use Lookup OWASP / Lookup CWE to find the canonical reference"
                ),
            )
        )

    # CVSS
    try:
        recomputed = calculate_cvss_score(draft.cvss_vector)
    except ValueError as exc:
        issues.append(
            ValidationIssue(
                section="cvss",
                severity="error",
                message=f"cvss_vector is invalid: {exc}",
            )
        )
    else:
        if abs(recomputed - draft.cvss_score) > 0.05:
            issues.append(
                ValidationIssue(
                    section="cvss",
                    severity="error",
                    message=(
                        f"cvss_score ({draft.cvss_score}) does not match the vector "
                        f"({recomputed} computed); use Calculate CVSS Score"
                    ),
                )
            )

    # CWE
    if CWE.get(draft.cwe_id) is None:
        issues.append(
            ValidationIssue(
                section="cwe",
                severity="warning",
                message=(
                    f"CWE-{draft.cwe_id} is not a recognised MITRE CWE id;"
                    " double-check via Lookup CWE"
                ),
            )
        )

    ok = not any(i.severity == "error" for i in issues)
    return ValidationReport(ok=ok, issues=issues)


# Rendering


def render_draft_markdown(draft: ReportDraft) -> str:
    """Render a draft into H1 markdown using the report template."""
    cwe = CWE.get(draft.cwe_id)
    cwe_name = cwe.name if cwe else "Other"
    steps = "\n".join(f"{i + 1}. {step}" for i, step in enumerate(draft.steps_to_reproduce))
    evidence_block = textwrap.indent(draft.evidence[:_EVIDENCE_LIMIT], "  ")
    return _REPORT_TEMPLATE.format(
        title=draft.title,
        summary=draft.summary,
        vuln_class=draft.vuln_class,
        severity=_SEVERITY_LABELS[draft.severity],
        cvss_score=draft.cvss_score,
        cvss_vector=draft.cvss_vector,
        cwe=draft.cwe_id,
        cwe_name=cwe_name,
        target=draft.target,
        description=draft.description,
        steps=steps,
        evidence=evidence_block,
        impact=draft.impact,
        remediation=draft.remediation,
        timestamp=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
    )


# Draft persistence


def _drafts_dir() -> Path:
    return runtime.run_dir() / _DRAFTS_SUBDIR


def draft_path(finding_index: int) -> Path:
    """Return the path of the draft file for ``finding_index``."""
    return _drafts_dir() / f"{finding_index:03d}.json"


def save_draft(draft: ReportDraft) -> Path:
    """Persist a draft to ``<run_dir>/drafts/<idx:03d>.json``."""
    path = draft_path(draft.finding_index)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(draft.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_draft(finding_index: int) -> ReportDraft:
    """Load a previously saved draft. Raises FileNotFoundError if absent."""
    path = draft_path(finding_index)
    if not path.is_file():
        raise FileNotFoundError(f"no draft for finding {finding_index} at {path}")
    return ReportDraft.model_validate_json(path.read_text(encoding="utf-8"))


def load_drafts() -> list[ReportDraft]:
    """Load every draft in the current run, ordered by finding_index."""
    dir_ = _drafts_dir()
    if not dir_.is_dir():
        return []
    drafts: list[ReportDraft] = []
    for path in sorted(dir_.glob("*.json")):
        drafts.append(ReportDraft.model_validate_json(path.read_text(encoding="utf-8")))
    return drafts


# Verified-finding lookup


def load_verified(verified_path: Path) -> list[VerifiedVulnerability]:
    """Load the VR's verified.json into VerifiedVulnerability instances."""
    raw = json.loads(verified_path.read_text(encoding="utf-8"))
    return [VerifiedVulnerability.model_validate(v) for v in raw]


# Finalisation


class FinalisationError(RuntimeError):
    """Raised when finalise_drafts is called but at least one draft has hard
    validation errors or is missing entirely."""


def finalise_drafts(
    programme_handle: str,
    summary: str,
    expected_count: int,
) -> Path:
    """Validate every draft, render markdown, build DisclosureReport per draft,
    and write ``reports.json`` for the Disclosure Coordinator.

    Refuses to finalise if any draft is missing or has hard validation errors.
    """
    drafts = load_drafts()
    if len(drafts) != expected_count:
        missing = expected_count - len(drafts)
        raise FinalisationError(
            f"expected {expected_count} drafts, found {len(drafts)} "
            f"({missing} missing); draft each verified finding before finalising"
        )

    failures: list[tuple[int, list[ValidationIssue]]] = []
    for draft in drafts:
        report = validate_draft(draft)
        if not report.ok:
            failures.append(
                (draft.finding_index, [i for i in report.issues if i.severity == "error"])
            )

    if failures:
        lines = ["one or more drafts have unresolved errors:"]
        for idx, issues in failures:
            for issue in issues:
                lines.append(f"  - draft {idx} / {issue.section}: {issue.message}")
        raise FinalisationError("\n".join(lines))

    reports: list[DisclosureReport] = []
    for draft in drafts:
        cwe = CWE.get(draft.cwe_id)
        vuln = VerifiedVulnerability(
            title=draft.title,
            vuln_class=draft.vuln_class,
            target=draft.target,
            severity=draft.severity,
            cvss_score=draft.cvss_score,
            cvss_vector=draft.cvss_vector,
            description=draft.description,
            steps_to_reproduce=draft.steps_to_reproduce,
            evidence=draft.evidence,
            impact=draft.impact,
            remediation=draft.remediation,
        )
        body = render_draft_markdown(draft)
        reports.append(
            DisclosureReport(
                programme_handle=programme_handle,
                title=draft.title,
                vulnerability=vuln,
                summary=summary,
                body_markdown=body,
                weakness_id=cwe.cwe_id if cwe else None,
                impact_statement=draft.impact,
            )
        )

    out_path = runtime.run_dir() / "reports.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps([r.model_dump(mode="json") for r in reports], default=str),
        encoding="utf-8",
    )
    return out_path


# Disclosure Coordinator compatibility


def save_report(report: DisclosureReport) -> Path:
    """Save a report to the configured reports directory. Returns the file path."""
    reports_dir = Path(config.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    safe_title = report.title.replace(" ", "_").replace("/", "-")[:60]
    filename = reports_dir / f"{timestamp}_{report.programme_handle}_{safe_title}.md"

    filename.write_text(report.body_markdown, encoding="utf-8")
    return filename
