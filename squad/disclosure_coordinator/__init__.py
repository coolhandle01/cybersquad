"""Disclosure Coordinator - submits finalised reports to HackerOne.

The agent's tools live in the ``tools`` sub-package
(``tools.submission``); this module imports each wrapper, assembles
``MEMBER.tools``, and re-exports both the wrappers and their args_schema
classes so existing consumers (tests, ``crew.py``, the contract tests in
``tests/squad/disclosure_coordinator/test_args_schemas.py``) keep
importing from ``squad.disclosure_coordinator`` directly.
"""

from pathlib import Path

from squad import SquadMember, read_run_file_tool, read_run_filelist_tool
from squad.disclosure_coordinator.tools.submission import (
    _CheckDuplicateArgs,
    _SubmitReportArgs,
    check_duplicate_tool,
    submit_report_tool,
)
from squad.tools.workspace_tools import _ListRunFilesArgs, _ReadRunFileArgs

MEMBER = SquadMember(
    dir=Path(__file__).parent,
    tools=[
        submit_report_tool,
        check_duplicate_tool,
        read_run_filelist_tool,
        read_run_file_tool,
    ],
    schemas={
        "Submit Report": _SubmitReportArgs,
        "Check H1 Duplicate": _CheckDuplicateArgs,
        # Shared workspace wrappers (re-exported via squad.tools.workspace_tools)
        "List Run Files": _ListRunFilesArgs,
        "Read Run File": _ReadRunFileArgs,
    },
)

__all__ = [  # noqa: RUF022 - grouped by purpose, not alphabetised
    # Public API
    "MEMBER",
    # Wrappers
    "submit_report_tool",
    "check_duplicate_tool",
    # args_schema classes (re-exported so test imports stay stable)
    "_SubmitReportArgs",
    "_CheckDuplicateArgs",
]
