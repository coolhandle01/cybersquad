"""Technical Author - writes professional H1-format disclosure reports.

The agent's tools live in the ``tools`` sub-package (``tools.authoring``);
this module imports each wrapper, assembles ``MEMBER.tools``, and re-
exports both the wrappers and their args_schema classes so existing
consumers (tests, ``crew.py``, the contract tests in
``tests/squad/technical_author/test_args_schemas.py``) keep importing
from ``squad.technical_author`` directly.
"""

from pathlib import Path

from squad import SquadMember, read_run_file_tool, read_run_filelist_tool
from squad.technical_author.tools.authoring import (
    _DraftReportArgs,
    _FinaliseReportsArgs,
    _SanitiseEvidenceArgs,
    _TaCalculateCvssArgs,
    _TaListProgrammeReportsArgs,
    _TaLookupCweArgs,
    _TaLookupOwaspArgs,
    calculate_cvss_tool,
    draft_report_tool,
    finalise_reports_tool,
    list_programme_reports_tool,
    lookup_cwe_tool,
    lookup_owasp_tool,
    sanitise_evidence_tool,
)
from squad.tools.workspace_tools import _ListRunFilesArgs, _ReadRunFileArgs

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
        # Shared workspace wrappers (re-exported via squad.tools.workspace_tools)
        "List Run Files": _ListRunFilesArgs,
        "Read Run File": _ReadRunFileArgs,
    },
)

__all__ = [  # noqa: RUF022 - grouped by purpose, not alphabetised
    # Public API
    "MEMBER",
    # Wrappers
    "calculate_cvss_tool",
    "draft_report_tool",
    "finalise_reports_tool",
    "list_programme_reports_tool",
    "lookup_cwe_tool",
    "lookup_owasp_tool",
    "sanitise_evidence_tool",
    # args_schema classes (re-exported so test imports stay stable)
    "_DraftReportArgs",
    "_FinaliseReportsArgs",
    "_SanitiseEvidenceArgs",
    "_TaCalculateCvssArgs",
    "_TaListProgrammeReportsArgs",
    "_TaLookupCweArgs",
    "_TaLookupOwaspArgs",
]
