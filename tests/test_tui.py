"""tests/test_tui.py - cybersquad's thin TUI wrapper over the crewui library.

The generic TUI moved to crewui; cybersquad keeps only ``CybersquadTUI``, a
subclass of ``crewui.CrewAIPipelineTUI``. These tests pin the two things
``main.py`` relies on: the wrapper is that subclass, and it accepts the
host-injected construction contract unchanged.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest

if TYPE_CHECKING:
    from crewai import Crew

pytestmark = pytest.mark.unit


def test_cybersquad_tui_subclasses_the_crewui_base() -> None:
    from crewui import CrewAIPipelineTUI

    from tools.tui import CybersquadTUI

    assert issubclass(CybersquadTUI, CrewAIPipelineTUI)


def test_constructor_accepts_the_host_contract() -> None:
    from tools.tui import CybersquadTUI

    crew = cast("Crew", SimpleNamespace(tasks=[], step_callback=None))
    app = CybersquadTUI(
        crew=crew,
        record_prefix="cybersquad",
        pipeline_name="Bug Bounty #test",
        dry_run=True,
        on_start=lambda: None,
        on_complete=lambda _result: None,
        get_token_cost=lambda _in, _out: 0.0,
    )
    assert app._record_prefix == "cybersquad"
