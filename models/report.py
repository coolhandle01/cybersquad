"""
models/report.py - typed shape for the Technical Author's drafted
report content.

Carries the LLM-authored prose (``AuthoredDraft``) the agent fills
in to draft a vulnerability report for one verified finding. The
full ``ReportDraft`` record - which merges the LLM-authored prose
with carry-forward fields from the VR's verified finding - lives next
to the report-persistence logic in ``tools/report_tools.py``.

Lives in models/ rather than tools/ because ``AuthoredDraft`` is the
contract the LLM sees as the args_schema of ``Draft Vulnerability
Report``: every field carries a ``Field(description=...)`` because
the per-field description is what teaches the agent the report
quality gate's grammar.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from models.nvd import CvssVector


class AuthoredDraft(BaseModel):
    """The LLM-authored half of one report draft.

    The other half - target / vuln_class / severity / cvss_score - is
    carry-forward from the VR's verified finding at the same
    ``finding_index`` and is not the LLM's to author. ``Draft
    Vulnerability Report``'s wrapper merges these two halves into the
    full ``ReportDraft`` record before running the quality gate.
    """

    title: str = Field(
        description=(
            "H1-format title following ``[Type] in [Component/Endpoint]"
            " allows [Outcome]``. The validator refuses generic titles -"
            " be specific about the component AND the outcome. Pair"
            " with ``List Programme Reports`` to check for collisions"
            " against existing submissions before drafting."
        ),
    )
    summary: str = Field(
        description=(
            "2-3 sentences naming root cause + location + concrete"
            " impact. This is the first thing a triager reads; if it"
            " does not name a concrete impact, the report ranks lower."
        ),
    )
    description: str = Field(
        description=(
            "Developer-focused explanation of WHY the code is"
            " vulnerable - the underlying class of flaw, not the"
            " reproduction steps (those go in ``steps_to_reproduce``)."
        ),
    )
    steps_to_reproduce: list[str] = Field(
        description=(
            "Minimal numbered list a triager can replay verbatim against"
            " the live target to reproduce the finding. Each entry is"
            " one reproduction step naming the tool used, the command /"
            " request, the expected response excerpt, and (where the"
            " marker is buried in a large payload) a pointer to the"
            " supporting evidence so the triager can verify the claim"
            " without re-running discovery. Example shape per step:"
            " ``Use sqlmap to confirm injection at /search?q. Run:"
            " ``sqlmap -u 'https://victim.example.com/search?q=test'"
            " --batch``. The ``[INFO]`` line citing ``boolean-based"
            " blind`` appears in the response and is captured in the"
            " attached evidence (grep ``boolean-based blind`` in the"
            " sanitised log).`` The validator refuses steps under 10"
            " characters - prefer one fully-formed step over several"
            " stubs."
        ),
    )
    # FIXME #156: the supporting-evidence / replay-log handoff this step
    # list references is sketched in the per-step "attached evidence"
    # pointer above but is not yet a workspace-typed artefact; triagers
    # verify claims against the live target until it lands.
    evidence: str = Field(
        description=(
            "PRE-SANITISED tool output / HTTP excerpt. Run ``Sanitise"
            " Evidence`` first to strip credentials, cookies, and"
            " secret-shaped key=value pairs - the disclosure is"
            " private, but the report is permanent and a leaked"
            " credential cannot be quietly removed once filed."
        ),
    )
    impact: str = Field(
        description=(
            "Specific named data / system and the worst realistic"
            " outcome. The validator refuses hand-wavy language"
            " (``could compromise``, ``potential``) - this section is"
            " what the programme uses to band severity."
        ),
    )
    remediation: str = Field(
        description=(
            "Actionable fix paired with an OWASP or CWE URL citation."
            " The validator refuses remediations that name no fix or"
            " carry no citation - use ``Lookup CWE`` / ``Lookup OWASP"
            " Guidance`` to find the matching URL."
        ),
    )
    # CvssVector validates the vector's *structure* (CVSS:3.x prefix +
    # well-formed metric tokens) at args_schema time; ``calculate_cvss_score``
    # in the wrapper remains the source of truth for metric semantics + score.
    cvss_vector: CvssVector = Field(
        description=(
            "Full CVSS 3.1 vector. The wrapper recomputes ``cvss_score``"
            " and the validator refuses drafts where the score does not"
            " match the declared severity. Use ``Calculate CVSS Score``"
            " upstream to double-check."
        ),
    )
    # Bare int: the agent authors the id. ``validate_draft`` resolves it
    # against the corpus (``CWE.get``) and warns on a miss - keeping the draft
    # args_schema a plain int rather than a nested CWE object the LLM would
    # have to construct.
    cwe_id: int = Field(
        description=(
            "Numeric CWE identifier matching the entry from ``Lookup"
            " CWE`` (e.g. ``89``). Validated against the MITRE corpus when"
            " the draft is checked; an unknown id is flagged before H1"
            " submission."
        ),
    )


__all__ = ["AuthoredDraft"]
