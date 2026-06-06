"""
models.finding - the vuln-pipeline data shapes (PT -> VR -> TA).

``RawFinding`` is the unverified output of an automated probe;
``VerifiedVulnerability`` is the post-triage shape the Technical Author
turns into a report; ``RawFindingSummary`` is the compact slice the VR's
List Raw Findings tool returns. All three carry a ``Severity`` (from
``models.nvd``).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field

from models.nvd import CvssVector, Severity

# Context-marker neutralisation for tool-captured evidence (defence 2 of the
# cybersquad-models prompt-injection policy: "constrain shape at the model
# boundary"). ``evidence`` holds verbatim external content - HTTP bodies,
# banners, the reflected payloads of probes like the prompt-injection check -
# that is serialised to JSON and read back into an agent's context (the VR's
# Read Raw Finding tool return, and downstream via CrewAI's divider-joined task
# context). A payload imitating CrewAI's task-output divider, a chat template's
# control token, or a Markdown heading is an indirect prompt injection /
# context-confusion vector (OWASP LLM01:2025,
# https://genai.owasp.org/llmrisk/llm01-prompt-injection/). This is distinct
# from tools.report_tools.sanitise_evidence, which redacts *secrets* at
# report-authoring time; the two compose.
#
# CrewAI joins prior task outputs with DIVIDERS = "\n\n----------\n\n"
# (crewai/utilities/formatter.py, pinned crewai>=1.14.0). The run-length
# threshold of 4 sits above a lone Markdown thematic break (3) and well below
# that 10-character literal, so the divider is neutralised robustly without the
# brittleness of matching the exact literal (which moves with the pin).
_DIVIDER_LINE = re.compile(r"[ \t]*[-=]{4,}[ \t]*")
_CONTROL_TOKEN = re.compile(r"<\|[^|>\r\n]{0,64}\|>")
_HEADING_LINE = re.compile(r"(?m)^([ \t]*)(#{1,6})([ \t])")


def _neutralise_context_markers(text: str) -> str:
    """Defang text that could imitate an agent-context boundary.

    Idempotent: chat-template control tokens (``<|im_end|>`` and kin) collapse
    to ``[control-token]``, a leading Markdown heading marker is backslash-
    escaped, and a divider line (a run of dashes or equals) collapses to
    ``[divider]``. None of the replacements re-match, so running this twice
    equals running it once.
    """
    text = _CONTROL_TOKEN.sub("[control-token]", text)
    text = _HEADING_LINE.sub(r"\1\\\2\3", text)
    return "\n".join(
        "[divider]" if _DIVIDER_LINE.fullmatch(line) else line for line in text.split("\n")
    )


# A str whose context-boundary markers are neutralised at validation time.
NeutralisedText = Annotated[str, AfterValidator(_neutralise_context_markers)]


class RawFinding(BaseModel):
    """An unverified potential vulnerability from automated tooling."""

    title: str
    vuln_class: str
    target: str
    # Tool-captured external text; neutralise context-boundary markers (defence 2).
    evidence: NeutralisedText
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
    # Carries RawFinding.evidence forward; neutralise on this path too (defence 2).
    evidence: NeutralisedText
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
