"""
models/triage.py - typed shapes for the Vulnerability Researcher's
triage pass.

Carries the LLM-authored assessment content (``AuthoredAssessment``)
the agent fills in to triage one raw finding, and the
``SeverityDecision`` enum that one of its fields takes. The full
``TriageAssessment`` record - which merges the LLM-authored content
with carry-forward fields from the PT's raw finding - lives next to
the assessment-persistence logic in ``tools/triage_tools.py``.

Lives in models/ rather than tools/ because ``AuthoredAssessment`` is
the contract the LLM sees as the args_schema of ``Assess Raw
Finding``: every field carries a ``Field(description=...)`` because
the per-field description is what teaches the agent the triage
quality gate's grammar.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from models.nvd import CvssVector, Severity


class SeverityDecision(StrEnum):
    """How the VR's severity call relates to the PT's severity_hint."""

    KEEP = "keep"
    RAISE = "raise"
    LOWER = "lower"


class AuthoredAssessment(BaseModel):
    """The LLM-authored half of one triage assessment.

    The other half - target / vuln_class / severity_hint - is carry-
    forward from the PT's raw finding at the same ``finding_index`` and
    is not the LLM's to author. ``Assess Raw Finding``'s wrapper merges
    these two halves into the full ``TriageAssessment`` record before
    running the quality gate.
    """

    severity_decision: SeverityDecision = Field(
        description=(
            "How this severity call relates to the PT's"
            " ``severity_hint``: one of ``keep`` (you agree with the PT),"
            " ``raise`` (your analysis warrants a higher band - explain"
            " why in ``severity_rationale``), or ``lower`` (your analysis"
            " warrants a lower band)."
        ),
    )
    severity: Severity = Field(
        description=(
            "Final severity band after the decision: one of ``critical``"
            " / ``high`` / ``medium`` / ``low`` / ``informational``. Has"
            " to match the band the recomputed CVSS score falls into -"
            " mis-banding the score loses the assessment."
        ),
    )
    severity_rationale: str = Field(
        description=(
            "1-2 sentences justifying the severity call. Required even"
            " when ``severity_decision`` is ``keep``; the rationale is"
            " surfaced in the briefing to the Technical Author."
        ),
    )
    cvss_vector: CvssVector = Field(
        description=(
            "Full CVSS 3.1 vector string"
            " (``CVSS:3.1/AV:<n>/AC:<n>/PR:<n>/UI:<n>/S:<n>/C:<n>/I:<n>"
            "/A:<n>``). ``cvss_score`` is recomputed from this vector and"
            " verified against the declared ``severity`` band. Use"
            " ``Calculate CVSS Score`` first if you want to double-check"
            " the score before submitting."
        ),
    )
    title: str = Field(
        description=(
            "Short, descriptive title. The Technical Author may rewrite"
            " for H1 format, but keep it informative enough that the"
            " briefing reads usefully on its own."
        ),
    )
    description: str = Field(
        description=(
            "Root-cause explanation aimed at a developer audience. The"
            " quality gate refuses overly short descriptions - give the"
            " reader the WHY, not just the what."
        ),
    )
    steps_to_reproduce: list[str] = Field(
        description=(
            "Numbered steps a triager can follow verbatim to reproduce"
            " the issue. The Technical Author refines them into the"
            " report; ship them concrete enough that the refinement is"
            " editing, not authoring from scratch."
        ),
    )
    impact: str = Field(
        description=(
            "Specific - name the data / system at risk and the worst"
            " realistic outcome. Hand-wavy language (``could compromise``,"
            " ``potential``) is rejected by the quality gate; the"
            " report's impact section is what the programme uses to band"
            " severity."
        ),
    )
    remediation: str = Field(
        description=(
            "Actionable fix paired with an OWASP cheat-sheet or CWE URL"
            " citation. The gate refuses remediations that name no fix"
            " or carry no citation - use ``Lookup CWE`` / ``Lookup OWASP"
            " Guidance`` to find the matching URL."
        ),
    )


__all__ = ["AuthoredAssessment", "SeverityDecision"]
