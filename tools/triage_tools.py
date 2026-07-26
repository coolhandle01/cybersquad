"""
tools/triage_tools.py - Triage authoring primitives for the Vulnerability
Researcher.

The VR's job is to turn a Penetration Tester's RawFinding into a
VerifiedVulnerability whose description, impact, and remediation pass the
Technical Author's draft-validation gate. The agent does the work; this module
provides the supporting primitives:

* ``TriageAssessment`` / ``DiscardEntry`` - per-finding artefacts the VR
  composes and persists under ``<run_dir>/assessments/NNN.json`` and
  ``<run_dir>/discards/NNN.json``.
* ``validate_assessment(assessment, raw, programme)`` - quality gate. Returns
  the issue list. Hard errors block ``finalise_triage``.
* ``save_assessment`` / ``save_discard`` / ``load_*`` - persistence.
* ``finalise_triage(programme_handle, raw_count)`` - validate every
  assessment, build a ``VerifiedVulnerability`` per accepted one, and write
  ``verified.json`` for the Technical Author. Refuses on hard errors or
  unprocessed raw findings.
* ``above_floor`` / ``in_scope`` - the discard gates the agent's tools
  enforce. Moved here from ``tools/pentest/triage.py`` so the triage flow
  is self-contained.

Hand-wavy-impact detection and CVSS scoring are reused from
``tools/report_tools.py`` - the same prose-quality invariants apply at both
the VR and TA boundaries.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

import runtime
from config import config
from models import RawFinding, Severity, VerifiedVulnerability
from models.h1 import Programme
from tools._helpers import _SEVERITY_FLOOR_ORDER
from tools.recon.scope import filter_in_scope, host_of
from tools.report_tools import _HAND_WAVY_IMPACT, _URL, calculate_cvss_score

_ASSESSMENTS_SUBDIR = "assessments"
_DISCARDS_SUBDIR = "discards"

# The literal boilerplate the old triage_findings function produced. If the
# agent submits this verbatim it means they short-circuited the analysis.
_STALE_DESCRIPTION = re.compile(r"automated detection of", re.IGNORECASE)
_STALE_IMPACT = re.compile(r"pending manual review", re.IGNORECASE)
_STALE_STEP = "observe the following evidence:"


# Enumerations


# SeverityDecision lives in models/triage.py per the typed-shapes-live-
# in-models rule. Re-exported here so existing ``from tools.triage_tools
# import SeverityDecision`` consumers keep working; the canonical
# import path is ``from models import SeverityDecision``. Deferred-import
# context documented at https://docs.astral.sh/ruff/rules/module-import-not-at-top-of-file/
from models.triage import SeverityDecision  # noqa: E402 - re-export at module bottom


class DiscardReason(StrEnum):
    """Canonical reasons a raw finding does not make it into verified.json."""

    OUT_OF_SCOPE = "out_of_scope"
    BELOW_FLOOR = "below_floor"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    NON_EXPLOITABLE = "non_exploitable"


# Scope / floor gates


def above_floor(severity: Severity) -> bool:
    """True when ``severity`` is at or above the configured min-severity floor."""
    floor = Severity(config.scan.min_severity)
    return _SEVERITY_FLOOR_ORDER.index(severity) >= _SEVERITY_FLOOR_ORDER.index(floor)


def in_scope(target: str, programme: Programme) -> bool:
    """True when ``target``'s hostname is in the programme's structured scope."""
    return bool(filter_in_scope([host_of(target)], programme))


# Models


class TriageAssessment(BaseModel):
    """One VR-authored assessment for an accepted raw finding."""

    finding_index: int
    target: str
    vuln_class: str

    # PT hint, retained for comparison
    severity_hint: Severity
    severity_decision: SeverityDecision
    severity: Severity
    severity_rationale: str

    cvss_vector: str
    cvss_score: float

    # Authored prose
    title: str
    description: str
    steps_to_reproduce: list[str]
    impact: str
    remediation: str

    assessed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DiscardEntry(BaseModel):
    """One VR-authored discard explanation for a raw finding."""

    finding_index: int
    target: str
    vuln_class: str
    severity_hint: Severity
    reason: DiscardReason
    rationale: str
    discarded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# Validation


class TriageValidationIssue(BaseModel):
    """One issue produced by validate_assessment."""

    section: str
    severity: str  # "error" (blocks finalise) or "warning" (advisory)
    message: str


class TriageValidationReport(BaseModel):
    """Result of validating one assessment."""

    ok: bool
    issues: list[TriageValidationIssue] = Field(default_factory=list)


class AssessmentResult(BaseModel):
    """Return shape of the Assess Raw Finding tool.

    ``path`` is the workspace-relative location of the persisted assessment
    (e.g. ``assessments/000.json``); ``validation`` is the quality-gate
    report for the assessment that was just authored. The pair lives on a
    single model so the agent does not have to remember which keys to
    inspect on a bare dict.
    """

    path: str
    validation: TriageValidationReport


class DiscardResult(BaseModel):
    """Return shape of the Discard Finding tool.

    ``path`` is the workspace-relative location of the persisted discard
    entry (e.g. ``discards/000.json``).
    """

    path: str


def _count_steps_too_short(steps: list[str]) -> list[int]:
    """Return 1-based indices of steps whose stripped length is < 10."""
    return [n for n, s in enumerate(steps, 1) if len(s.strip()) < 10]


def validate_assessment(
    assessment: TriageAssessment,
    raw: RawFinding,
    programme: Programme,
) -> TriageValidationReport:
    """Apply quality heuristics to an assessment. Returns the issue list.

    ``raw`` is the corresponding raw finding from findings.json - used to
    enforce target/vuln_class/severity_hint consistency. ``programme`` is the
    parsed Programme - used for scope and severity-floor checks. The same
    hand-wavy-impact and URL-citation rules the Technical Author enforces are
    applied here so the TA never sees an assessment that would fail its own
    draft gate.
    """
    issues: list[TriageValidationIssue] = []

    # Consistency with the raw finding (must not silently rewrite identifiers)
    if assessment.target != raw.target:
        issues.append(
            TriageValidationIssue(
                section="target",
                severity="error",
                message=(
                    f"target {assessment.target!r} does not match the raw finding "
                    f"target {raw.target!r}; do not rewrite target during triage"
                ),
            )
        )
    if assessment.vuln_class != raw.vuln_class:
        issues.append(
            TriageValidationIssue(
                section="vuln_class",
                severity="error",
                message=(
                    f"vuln_class {assessment.vuln_class!r} does not match the raw "
                    f"finding vuln_class {raw.vuln_class!r}"
                ),
            )
        )
    if assessment.severity_hint != raw.severity_hint:
        issues.append(
            TriageValidationIssue(
                section="severity_hint",
                severity="error",
                message=(
                    f"severity_hint {assessment.severity_hint!r} does not match the "
                    f"raw finding severity_hint {raw.severity_hint!r}"
                ),
            )
        )

    # Scope / floor: hard errors that imply a discard, not an assessment
    if not in_scope(assessment.target, programme):
        issues.append(
            TriageValidationIssue(
                section="target",
                severity="error",
                message=(
                    f"target is out of programme scope; use Discard Finding with "
                    f"reason='{DiscardReason.OUT_OF_SCOPE}' instead"
                ),
            )
        )
    if not above_floor(assessment.severity):
        issues.append(
            TriageValidationIssue(
                section="severity",
                severity="error",
                message=(
                    f"severity {assessment.severity} is below the configured floor; "
                    f"use Discard Finding with reason='{DiscardReason.BELOW_FLOOR}' instead"
                ),
            )
        )

    # Severity rationale
    if len(assessment.severity_rationale.strip()) < 30:
        issues.append(
            TriageValidationIssue(
                section="severity_rationale",
                severity="error",
                message=(
                    "severity_rationale too thin; justify the call in one or two "
                    "sentences (exploit prerequisites, blast radius, business impact)"
                ),
            )
        )

    # Severity decision consistency
    if assessment.severity_decision == SeverityDecision.KEEP:
        if assessment.severity != assessment.severity_hint:
            issues.append(
                TriageValidationIssue(
                    section="severity_decision",
                    severity="error",
                    message=(
                        "severity_decision='keep' but severity differs from "
                        "severity_hint; set decision to 'raise' or 'lower'"
                    ),
                )
            )
    elif assessment.severity == assessment.severity_hint:
        issues.append(
            TriageValidationIssue(
                section="severity_decision",
                severity="error",
                message=(
                    f"severity_decision='{assessment.severity_decision}' but severity "
                    "matches severity_hint; set decision to 'keep'"
                ),
            )
        )

    # Title (soft - the TA rewrites)
    if len(assessment.title.strip()) < 20:
        issues.append(
            TriageValidationIssue(
                section="title",
                severity="warning",
                message=(
                    "title is shorter than 20 chars; the TA can rewrite but a "
                    "descriptive title makes the briefing easier to scan"
                ),
            )
        )

    # Description
    if _STALE_DESCRIPTION.search(assessment.description):
        issues.append(
            TriageValidationIssue(
                section="description",
                severity="error",
                message=(
                    "description contains the legacy 'Automated detection of...' "
                    "boilerplate; describe the root cause in your own words"
                ),
            )
        )
    if len(assessment.description.strip()) < 100:
        issues.append(
            TriageValidationIssue(
                section="description",
                severity="error",
                message=(
                    "description too thin; explain the root cause as if briefing "
                    "the TA - what the bug is, why it works, what code path is "
                    "responsible"
                ),
            )
        )

    # Steps
    if len(assessment.steps_to_reproduce) < 2:
        issues.append(
            TriageValidationIssue(
                section="steps_to_reproduce",
                severity="error",
                message="at least 2 numbered steps are required",
            )
        )
    short_indices = _count_steps_too_short(assessment.steps_to_reproduce)
    for n in short_indices:
        issues.append(
            TriageValidationIssue(
                section="steps_to_reproduce",
                severity="error",
                message=f"step {n} is too short to be reproducible",
            )
        )
    for n, step in enumerate(assessment.steps_to_reproduce, 1):
        if step.strip().lower() == _STALE_STEP:
            issues.append(
                TriageValidationIssue(
                    section="steps_to_reproduce",
                    severity="error",
                    message=(
                        f"step {n} is the legacy 'Observe the following evidence:' "
                        "placeholder; write the actual observable proof"
                    ),
                )
            )

    # Impact
    if len(assessment.impact.strip()) < 40:
        issues.append(
            TriageValidationIssue(
                section="impact",
                severity="error",
                message=(
                    "impact statement too short; name the data/system at risk, who "
                    "is affected, and the realistic worst outcome"
                ),
            )
        )
    if _HAND_WAVY_IMPACT.search(assessment.impact):
        issues.append(
            TriageValidationIssue(
                section="impact",
                severity="error",
                message=(
                    "impact statement uses hand-wavy language (e.g. 'could "
                    "compromise', 'potential'); be concrete about what an attacker "
                    "can actually do"
                ),
            )
        )
    if _STALE_IMPACT.search(assessment.impact):
        issues.append(
            TriageValidationIssue(
                section="impact",
                severity="error",
                message=(
                    "impact contains the legacy 'pending manual review' placeholder; "
                    "the manual review is your job - write the concrete impact"
                ),
            )
        )

    # Remediation
    if len(assessment.remediation.strip()) < 60:
        issues.append(
            TriageValidationIssue(
                section="remediation",
                severity="error",
                message="remediation too thin; give the developer a concrete fix",
            )
        )
    if not _URL.search(assessment.remediation):
        issues.append(
            TriageValidationIssue(
                section="remediation",
                severity="error",
                message=(
                    "remediation must cite an OWASP cheat-sheet or CWE URL; use "
                    "Lookup OWASP Guidance / Lookup CWE for canonical references"
                ),
            )
        )

    # CVSS
    try:
        recomputed = calculate_cvss_score(assessment.cvss_vector)
    except ValueError as exc:
        issues.append(
            TriageValidationIssue(
                section="cvss",
                severity="error",
                message=f"cvss_vector is invalid: {exc}",
            )
        )
    else:
        if abs(recomputed - assessment.cvss_score) > 0.05:
            issues.append(
                TriageValidationIssue(
                    section="cvss",
                    severity="error",
                    message=(
                        f"cvss_score ({assessment.cvss_score}) does not match the "
                        f"vector ({recomputed} computed); use Calculate CVSS Score"
                    ),
                )
            )
        else:
            implied = _severity_from_score(recomputed)
            if implied != assessment.severity:
                issues.append(
                    TriageValidationIssue(
                        section="cvss",
                        severity="warning",
                        message=(
                            f"CVSS score {recomputed} implies severity "
                            f"{implied} but assessment says {assessment.severity}; "
                            "consider revising the vector or severity"
                        ),
                    )
                )

    ok = not any(i.severity == "error" for i in issues)
    return TriageValidationReport(ok=ok, issues=issues)


# CVSS / severity bridge


_SEVERITY_BANDS: list[tuple[float, Severity]] = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
    (0.0, Severity.INFORMATIONAL),
]


def _severity_from_score(score: float) -> Severity:
    """The NVD severity band for ``score`` per the CVSS 3.1 qualitative scale."""
    for threshold, sev in _SEVERITY_BANDS:
        if score >= threshold:
            return sev
    return Severity.INFORMATIONAL


# Persistence


def _assessments_dir() -> Path:
    return runtime.run_dir() / _ASSESSMENTS_SUBDIR


def _discards_dir() -> Path:
    return runtime.run_dir() / _DISCARDS_SUBDIR


def assessment_path(finding_index: int) -> Path:
    return _assessments_dir() / f"{finding_index:03d}.json"


def discard_path(finding_index: int) -> Path:
    return _discards_dir() / f"{finding_index:03d}.json"


def save_assessment(assessment: TriageAssessment) -> Path:
    """Persist an assessment to ``<run_dir>/assessments/<idx:03d>.json``."""
    path = assessment_path(assessment.finding_index)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Discard any existing discard for the same index (the VR changed their mind).
    _drop_discard(assessment.finding_index)
    path.write_text(assessment.model_dump_json(indent=2), encoding="utf-8")
    return path


def save_discard(discard: DiscardEntry) -> Path:
    """Persist a discard to ``<run_dir>/discards/<idx:03d>.json``."""
    path = discard_path(discard.finding_index)
    path.parent.mkdir(parents=True, exist_ok=True)
    _drop_assessment(discard.finding_index)
    path.write_text(discard.model_dump_json(indent=2), encoding="utf-8")
    return path


def _drop_assessment(finding_index: int) -> None:
    path = assessment_path(finding_index)
    if path.is_file():
        path.unlink()


def _drop_discard(finding_index: int) -> None:
    path = discard_path(finding_index)
    if path.is_file():
        path.unlink()


def load_assessments() -> list[TriageAssessment]:
    """Load every assessment in the current run, ordered by finding_index."""
    dir_ = _assessments_dir()
    if not dir_.is_dir():
        return []
    return [
        TriageAssessment.model_validate_json(p.read_text(encoding="utf-8"))
        for p in sorted(dir_.glob("*.json"))
    ]


def load_discards() -> list[DiscardEntry]:
    """Load every discard in the current run, ordered by finding_index."""
    dir_ = _discards_dir()
    if not dir_.is_dir():
        return []
    return [
        DiscardEntry.model_validate_json(p.read_text(encoding="utf-8"))
        for p in sorted(dir_.glob("*.json"))
    ]


# Raw findings loader (deliberately not on workspace - typed return)


def load_raw_findings(findings_path: Path) -> list[RawFinding]:
    """Load raw findings from a findings.json path."""
    raw = json.loads(findings_path.read_text(encoding="utf-8"))
    return [RawFinding.model_validate(f) for f in raw]


# Finalisation


class TriageFinalisationError(RuntimeError):
    """Raised when finalise_triage cannot produce verified.json: missing
    coverage (an unassessed/undiscarded raw finding) or any assessment with
    hard validation errors."""


def finalise_triage(
    programme: Programme,
    raw_findings: list[RawFinding],
) -> Path:
    """Validate every assessment, build a ``VerifiedVulnerability`` per
    accepted one, and write ``verified.json`` for the Technical Author.

    Refuses to finalise if:
      * any raw finding is neither assessed nor discarded
      * any assessment has hard validation errors
      * a finding has both an assessment and a discard (ambiguous)

    Returns the path to the written verified.json (may contain zero entries
    if every finding was discarded - the TA briefing will explain).
    """
    assessments = load_assessments()
    discards = load_discards()

    assessed_idx = {a.finding_index for a in assessments}
    discarded_idx = {d.finding_index for d in discards}

    ambiguous = assessed_idx & discarded_idx
    if ambiguous:
        raise TriageFinalisationError(
            f"findings {sorted(ambiguous)} are both assessed and discarded; "
            "save_assessment / save_discard clear the other, so this should not "
            "happen - investigate"
        )

    all_idx = set(range(len(raw_findings)))
    missing = sorted(all_idx - assessed_idx - discarded_idx)
    if missing:
        raise TriageFinalisationError(
            f"raw findings {missing} have no assessment or discard; every finding "
            "must be either assessed or discarded before finalising"
        )

    raw_by_idx = dict(enumerate(raw_findings))
    failures: list[tuple[int, list[TriageValidationIssue]]] = []
    for assessment in assessments:
        raw = raw_by_idx[assessment.finding_index]
        report = validate_assessment(assessment, raw, programme)
        if not report.ok:
            failures.append(
                (
                    assessment.finding_index,
                    [i for i in report.issues if i.severity == "error"],
                )
            )

    if failures:
        lines = ["one or more assessments have unresolved errors:"]
        for idx, errs in failures:
            for err in errs:
                lines.append(f"  - assessment {idx} / {err.section}: {err.message}")
        raise TriageFinalisationError("\n".join(lines))

    verified: list[VerifiedVulnerability] = []
    for assessment in assessments:
        raw = raw_by_idx[assessment.finding_index]
        verified.append(
            VerifiedVulnerability(
                title=assessment.title,
                vuln_class=assessment.vuln_class,
                target=assessment.target,
                severity=assessment.severity,
                cvss_score=assessment.cvss_score,
                cvss_vector=assessment.cvss_vector,
                description=assessment.description,
                steps_to_reproduce=assessment.steps_to_reproduce,
                evidence=raw.evidence,
                impact=assessment.impact,
                remediation=assessment.remediation,
            )
        )

    out_path = runtime.run_dir() / "verified.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps([v.model_dump(mode="json") for v in verified], default=str),
        encoding="utf-8",
    )
    return out_path
