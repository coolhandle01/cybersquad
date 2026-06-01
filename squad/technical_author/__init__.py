"""Technical Author - writes professional H1-format disclosure reports."""

from pathlib import Path

from pydantic import BaseModel, Field

import runtime
from models import CWE, AuthoredDraft, OWASPEntry, ProgrammeReportSummary
from squad import SquadMember, cyber_tool, read_run_file_tool, read_run_filelist_tool
from squad.workspace_tools import _ListRunFilesArgs, _ReadRunFileArgs
from tools.h1_api import h1
from tools.owasp_data import lookup as owasp_lookup
from tools.report_tools import (
    FinalisationError,
    ReportDraft,
    ReportDraftResult,
    SanitisationReport,
    calculate_cvss_score,
    finalise_drafts,
    load_verified,
    sanitise_evidence,
    save_draft,
    validate_draft,
)
from tools.workspace import resolve_run_path


class _SanitiseEvidenceArgs(BaseModel):
    """Explicit args_schema for the Sanitise Evidence tool."""

    text: str = Field(
        description=(
            "Raw evidence text - HTTP request/response excerpts, tool"
            " output, captured headers - that may carry credentials,"
            " cookies, bearer tokens, JWTs, AWS keys, or other secret-"
            "shaped key=value pairs. Pass the unredacted text as it"
            " appears in the PT's raw finding; the wrapper returns a"
            " ``SanitisationReport`` carrying the redacted body, a list"
            " of redactions made, and any warnings. Payloads (XSS"
            " strings, SQL injection vectors, SSRF URLs) are"
            " deliberately NOT redacted - the triager needs the literal"
            " request that proves the issue. Run this before pasting"
            " evidence into ``Draft Vulnerability Report``."
        ),
    )


@cyber_tool("Sanitise Evidence", args_schema=_SanitiseEvidenceArgs)
def sanitise_evidence_tool(text: str) -> SanitisationReport:
    """
    Redact credentials, cookies, bearer tokens, JWTs, AWS keys and secret-shaped
    key=value pairs from a chunk of evidence so it is safe to inline in a
    public-by-default report. Returns {sanitised, redactions, warnings}.
    Payloads (XSS strings, SQL injection vectors, SSRF URLs) are deliberately
    NOT redacted - the disclosure is private and the triager needs the literal
    request that proves the issue. Run this on the Penetration Tester's raw
    evidence before pasting it into Draft Vulnerability Report.
    """
    return sanitise_evidence(text)


class _TaLookupCweArgs(BaseModel):
    """Explicit args_schema for the TA's Lookup CWE tool."""

    cwe_id: int = Field(
        description=(
            "The CWE id this finding maps to. For a CVE-backed finding,"
            " use the id ``NVD CVE Lookup`` returned (``CveEntry.cwe_ids``);"
            " otherwise the id of the weakness class the probe found"
            " (e.g. ``89`` for SQL injection, ``79`` for XSS). Returns"
            " MITRE's canonical name + description + URL to cite in the"
            " remediation section."
        ),
    )


@cyber_tool("Lookup CWE", args_schema=_TaLookupCweArgs)
def lookup_cwe_tool(cwe_id: int) -> list[CWE]:
    """
    Resolve a CWE id to MITRE's canonical name, description, and URL for the
    remediation section. Pass the id from NVD CVE Lookup (cwe_ids) for a
    CVE-backed finding, or the weakness-class id otherwise. Returns one entry,
    or an empty list if the id is not a real CWE.
    """
    cwe = CWE.get(cwe_id)
    return [cwe] if cwe else []


class _TaLookupOwaspArgs(BaseModel):
    """Explicit args_schema for the TA's Lookup OWASP Guidance tool."""

    query: str = Field(
        description=(
            "Free-text query against the OWASP Cheat Sheet index. Matches"
            " topic slug or title keyword (e.g. ``sql injection``,"
            " ``ssrf``, ``authorization``). Use to source the canonical"
            " ``cheatsheetseries.owasp.org`` URL cited in the"
            " Remediation section of the H1 report - the returned"
            " entry's ``key_principles`` are short, paste-friendly"
            " statements suitable for the report body."
        ),
    )


@cyber_tool("Lookup OWASP Guidance", args_schema=_TaLookupOwaspArgs)
def lookup_owasp_tool(query: str) -> list[OWASPEntry]:
    """
    Find OWASP Cheat Sheet entries that match a query (topic slug or title
    keyword such as "sql injection", "ssrf", "authorization"). Returns each
    match's title, key_principles (short, paste-friendly statements), and the
    canonical cheatsheetseries.owasp.org URL to cite in the Remediation
    section.
    """
    return list(owasp_lookup(query))


class _TaCalculateCvssArgs(BaseModel):
    """Explicit args_schema for the TA's Calculate CVSS Score tool.

    Same vector format as on the VR's copy. ``Draft Vulnerability
    Report`` re-runs the compute and refuses if the declared score
    does not match the recomputed value - a mis-formed vector here
    flips the verdict before the draft is even validated.
    """

    vector: str = Field(
        description=(
            "Full CVSS 3.1 vector string"
            " (``CVSS:3.1/AV:<n>/AC:<n>/PR:<n>/UI:<n>/S:<n>/C:<n>/I:<n>"
            "/A:<n>``, e.g."
            " ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``). Each"
            " metric must use the documented short codes; malformed"
            " vectors raise rather than silently scoring 0. Use this"
            " before drafting so the report's declared score matches"
            " what the validator recomputes."
        ),
    )


@cyber_tool("Calculate CVSS Score", args_schema=_TaCalculateCvssArgs)
def calculate_cvss_tool(vector: str) -> float:
    """
    Compute the CVSS 3.1 base score from a vector string such as
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. Returns a value in 0.0-10.0.
    Use this instead of guessing the score; Draft Vulnerability Report verifies
    that cvss_score matches the computed value before accepting the draft.
    """
    return calculate_cvss_score(vector)


class _TaListProgrammeReportsArgs(BaseModel):
    """Explicit args_schema for the TA's List Programme Reports tool."""

    page_size: int = Field(
        default=25,
        description=(
            "Number of reports to pull per H1 API page (default 25)."
            " Used to right-size the prior-art sample before drafting a"
            " distinct title - 25 is enough to spot collisions without"
            " a full sweep."
        ),
    )


@cyber_tool("List Programme Reports", args_schema=_TaListProgrammeReportsArgs)
def list_programme_reports_tool(page_size: int = 25) -> list[ProgrammeReportSummary]:
    """
    List recent public reports on this programme so you can write a title that
    is distinct from existing submissions. Returns each report's id, title,
    severity, and state. Use this BEFORE drafting if you suspect collision -
    the Disclosure Coordinator will reject duplicates at submission time and a
    well-differentiated title speeds up triage.
    """
    reports = h1.list_reports(runtime.programme_handle, page_size=page_size)
    return [
        ProgrammeReportSummary(
            report_id=r.get("id"),
            title=r.get("attributes", {}).get("title"),
            severity=r.get("attributes", {}).get("severity_rating"),
            state=r.get("attributes", {}).get("state"),
        )
        for r in reports
    ]


class _DraftReportArgs(BaseModel):
    """Explicit args_schema for the Draft Vulnerability Report tool.

    The LLM-authored content lives on ``AuthoredDraft`` (in
    ``models.report``) alongside the per-field descriptions; this
    schema wires that authored content to the VR's verified finding at
    ``finding_index``.
    """

    finding_index: int = Field(
        description=(
            "Zero-based index into ``verified.json``. Carries target /"
            " vuln_class / severity forward from the VR's verified"
            " entry so the draft cannot accidentally contradict the"
            " Vulnerability Researcher. Out-of-range refuses explicitly."
        ),
    )
    authored: AuthoredDraft = Field(
        description=(
            "Your authored report content: title / summary / description"
            " / steps_to_reproduce / evidence / impact / remediation /"
            " cvss_vector / cwe_id. Run ``Sanitise Evidence`` over your"
            " evidence section first - the disclosure is private but"
            " the report is permanent."
        ),
    )
    verified_path: str = Field(
        default="verified.json",
        description=(
            "Relative path to the VR's verified findings artefact"
            " (defaults to ``verified.json``). Override only when"
            " drafting against a non-default writer; the typical TA"
            " call accepts the default."
        ),
    )


@cyber_tool("Draft Vulnerability Report", args_schema=_DraftReportArgs)
def draft_report_tool(
    finding_index: int,
    authored: AuthoredDraft,
    verified_path: str = "verified.json",
) -> ReportDraftResult:
    """
    Draft a single H1-format report for one verified finding and run quality
    validation against it. The carried fields (target, vuln_class, severity)
    are pulled from verified.json at ``finding_index`` so you cannot
    accidentally contradict the Vulnerability Researcher.

    ``authored`` is the typed ``AuthoredDraft`` content: see the
    model's per-field descriptions for the contract on each section
    (title, summary, description, steps_to_reproduce, evidence,
    impact, remediation, cvss_vector, cwe_id).

    Returns a ReportDraftResult with the relative draft path and a
    ValidationReport. When validation.ok is false, re-run with the issues
    addressed - Finalise Reports refuses to consolidate drafts with
    unresolved errors.
    """
    verified = load_verified(resolve_run_path(verified_path))
    if finding_index < 0 or finding_index >= len(verified):
        raise ValueError(
            f"finding_index {finding_index} out of range "
            f"(verified.json has {len(verified)} findings)"
        )
    finding = verified[finding_index]
    # Both-shapes adapter: dict from CrewAI, model instance from tests.
    authored = AuthoredDraft.model_validate(authored)

    draft = ReportDraft(
        finding_index=finding_index,
        target=finding.target,
        vuln_class=finding.vuln_class,
        severity=finding.severity,
        cvss_vector=authored.cvss_vector,
        cvss_score=calculate_cvss_score(authored.cvss_vector),
        cwe_id=authored.cwe_id,
        title=authored.title.strip(),
        summary=authored.summary.strip(),
        description=authored.description.strip(),
        steps_to_reproduce=[s.strip() for s in authored.steps_to_reproduce],
        evidence=authored.evidence,
        impact=authored.impact.strip(),
        remediation=authored.remediation.strip(),
    )
    path = save_draft(draft)
    return ReportDraftResult(
        path=str(path.relative_to(path.parents[1])),
        validation=validate_draft(draft),
    )


class _FinaliseReportsArgs(BaseModel):
    """Explicit args_schema for the TA's Finalise Reports tool."""

    summary: str = Field(
        description=(
            "2-3 sentence executive summary covering the overall"
            " session - attached to every report in the consolidated"
            " manifest. Describe the surface tested and the breadth of"
            " what was found at a glance; the triager reads this"
            " before the per-finding body."
        ),
    )
    verified_path: str = Field(
        default="verified.json",
        description=(
            "Relative path to the VR's verified findings artefact"
            " (defaults to ``verified.json``). Override only when"
            " finalising against a non-default writer."
        ),
    )


@cyber_tool("Finalise Reports", args_schema=_FinaliseReportsArgs)
def finalise_reports_tool(
    summary: str,
    verified_path: str = "verified.json",
) -> str:
    """
    Roll up every draft in the current run into reports.json for the Disclosure
    Coordinator. Refuses if any draft is missing or has unresolved validation
    errors; the error message lists exactly which draft / section needs work.

    ``summary`` is a 2-3 sentence executive summary covering the overall
    session; it is attached to every report.

    Returns the bare filename "reports.json" on success.
    """
    verified = load_verified(resolve_run_path(verified_path))
    try:
        path = finalise_drafts(runtime.programme_handle, summary, expected_count=len(verified))
    except FinalisationError as exc:
        raise ValueError(str(exc)) from exc
    return path.name


MEMBER = SquadMember(
    dir=Path(__file__).parent,
    tools=[
        draft_report_tool,
        finalise_reports_tool,
        sanitise_evidence_tool,
        lookup_cwe_tool,
        lookup_owasp_tool,
        calculate_cvss_tool,
        list_programme_reports_tool,
        read_run_filelist_tool,
        read_run_file_tool,
    ],
    schemas={
        "Sanitise Evidence": _SanitiseEvidenceArgs,
        "Lookup CWE": _TaLookupCweArgs,
        "Lookup OWASP Guidance": _TaLookupOwaspArgs,
        "Calculate CVSS Score": _TaCalculateCvssArgs,
        "List Programme Reports": _TaListProgrammeReportsArgs,
        "Draft Vulnerability Report": _DraftReportArgs,
        "Finalise Reports": _FinaliseReportsArgs,
        # Shared workspace wrappers (re-exported via squad.workspace_tools)
        "List Run Files": _ListRunFilesArgs,
        "Read Run File": _ReadRunFileArgs,
    },
)
