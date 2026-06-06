"""Programme Manager - selects the highest-value H1 programme.

The agent's tools live in the ``tools`` sub-package (``tools.selection``);
this module imports each wrapper, assembles ``MEMBER.tools``, and re-
exports both the wrappers and their args_schema classes so existing
consumers (tests, ``crew.py``, the contract tests in
``tests/squad/programme_manager/test_args_schemas.py``) keep importing
from ``squad.programme_manager`` directly.
"""

from pathlib import Path

from squad import SquadMember
from squad.programme_manager.tools.selection import (
    _BrowseProgrammesArgs,
    _HydrateProgrammeArgs,
    _SaveProgrammeArgs,
    browse_programmes_tool,
    hydrate_programme_tool,
    save_programme_tool,
)

MEMBER = SquadMember(
    dir=Path(__file__).parent,
    tools=[browse_programmes_tool, hydrate_programme_tool, save_programme_tool],
    schemas={
        "Browse HackerOne Programmes": _BrowseProgrammesArgs,
        "Hydrate HackerOne Programme": _HydrateProgrammeArgs,
        "Save Selected Programme": _SaveProgrammeArgs,
    },
)

__all__ = [  # noqa: RUF022 - grouped by purpose, not alphabetised
    # Public API
    "MEMBER",
    # Wrappers
    "browse_programmes_tool",
    "hydrate_programme_tool",
    "save_programme_tool",
    # args_schema classes (re-exported so test imports stay stable)
    "_BrowseProgrammesArgs",
    "_HydrateProgrammeArgs",
    "_SaveProgrammeArgs",
]
