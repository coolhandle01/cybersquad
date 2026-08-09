"""
tools/research_tools.py - Attack-plan authoring primitives for the
Vulnerability Researcher.

The VR's research pass turns the OSINT Analyst's recon brief into a typed
attack plan: a list of probe-target hypotheses with expected severity
ceilings and the recon signals that justified each one. The agent does the
thinking; this module provides the supporting primitives:

* ``AttackForest`` / ``AttackTree`` (from ``models.attack``) - the
  artefact the agent composes.
* ``validate_attack_forest(plan)`` - quality gate. Returns the issue list
  (``AttackForestValidationReport`` from ``models.attack``). Hard errors
  block ``finalise_research``.
* ``finalise_research(plan)`` - validate, persist ``attack_forest.json`` for
  the Penetration Tester and re-read at triage time. Raises
  ``AttackForestFinalisationError`` (from ``models.attack``) on hard errors.
* ``load_attack_forest(path)`` - reverse direction. Deserialise
  ``attack_forest.json`` into a typed ``AttackForest`` so downstream agents
  (PT, VR at triage) consume a Pydantic model rather than a raw blob.

Mirrors the ``finalise_recon`` / ``finalise_triage`` pattern so the VR's
research artefact is a first-class workspace file alongside ``recon.json``
and ``verified.json``.
"""

from __future__ import annotations

from pathlib import Path

import runtime
from models.attack import (
    AttackForest,
    AttackForestFinalisationError,
    AttackForestValidationIssue,
    AttackForestValidationReport,
)

_ATTACK_FOREST_FILENAME = "attack_forest.json"


# Validation


def validate_attack_forest(plan: AttackForest) -> AttackForestValidationReport:
    """Apply quality heuristics to an AttackForest. Returns the issue list.

    Hard errors:
      * empty ``trees`` (no plan is not a plan)
      * any tree missing one of probe / target / rationale (empty after strip)
      * any tree whose ``recon_evidence`` is empty - the plan is supposed
        to be grounded in the OSINT Analyst's signals; an unevidenced
        hypothesis is the agent skipping the research pass.
    """
    issues: list[AttackForestValidationIssue] = []

    if not plan.trees:
        issues.append(
            AttackForestValidationIssue(
                section="trees",
                severity="error",
                message=(
                    "attack plan has no trees; produce at least one "
                    "probe-target hypothesis or explain in the briefing "
                    "why no probes are warranted"
                ),
            )
        )

    for n, tree in enumerate(plan.trees, 1):
        if not tree.probe.strip():
            issues.append(
                AttackForestValidationIssue(
                    section=f"trees[{n}].probe",
                    severity="error",
                    message="probe is required (CVE id or vulnerability-class name)",
                )
            )
        if not tree.target.strip():
            issues.append(
                AttackForestValidationIssue(
                    section=f"trees[{n}].target",
                    severity="error",
                    message="target is required (hostname or URL drawn from recon)",
                )
            )
        if not tree.rationale.strip():
            issues.append(
                AttackForestValidationIssue(
                    section=f"trees[{n}].rationale",
                    severity="error",
                    message="rationale is required (1-2 sentence why and what to look for)",
                )
            )
        if not tree.recon_evidence:
            issues.append(
                AttackForestValidationIssue(
                    section=f"trees[{n}].recon_evidence",
                    severity="error",
                    message=(
                        "recon_evidence must not be empty; cite the recon signals "
                        "(host, tech, port, endpoint pattern) that justified this probe"
                    ),
                )
            )

    ok = not any(i.severity == "error" for i in issues)
    return AttackForestValidationReport(ok=ok, issues=issues)


# Persistence / finalisation


def attack_forest_path() -> Path:
    """Return the on-disk path of attack_forest.json for the current run."""
    return runtime.run_dir() / _ATTACK_FOREST_FILENAME


def finalise_research(plan: AttackForest) -> Path:
    """Validate ``plan`` and write ``attack_forest.json`` to the run dir.

    Refuses on any hard validation error (see ``validate_attack_forest``).
    Returns the path to the written file.
    """
    report = validate_attack_forest(plan)
    if not report.ok:
        # validate_attack_forest only emits errors today, so no filter; if a
        # warning level is added later, surface it the same way.
        lines = ["attack plan has unresolved errors:"]
        lines.extend(f"  - {issue.section}: {issue.message}" for issue in report.issues)
        raise AttackForestFinalisationError("\n".join(lines))

    out_path = attack_forest_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    return out_path


def load_attack_forest(path: Path) -> AttackForest:
    """Deserialise ``attack_forest.json`` from ``path`` into a typed AttackForest.

    The reader half of the ``finalise_research`` contract: PT loads the plan
    before running probes, and the VR re-loads it at triage time to map
    findings back to the hypotheses that justified them. Raises
    ``FileNotFoundError`` if the file is missing - the caller surfaces a
    workflow error rather than silently reverting to a free-form briefing.
    """
    if not path.is_file():
        raise FileNotFoundError(f"attack plan not found at {path}")
    return AttackForest.model_validate_json(path.read_text(encoding="utf-8"))


__all__ = [
    "attack_forest_path",
    "finalise_research",
    "load_attack_forest",
    "validate_attack_forest",
]
