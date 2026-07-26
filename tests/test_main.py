"""
tests/test_main.py - covers the dry-run-vs-kickoff dispatch added by #144.

Only the new MCP-wrapping branches in ``main.main()`` are exercised here.
The two-line check is: dry-run does *not* enter the
``provisioned_mcp_tools()`` CM (no MCP subprocess starts during preview);
a full run *does*, and ``build_crew`` receives the registry the CM
yielded.
"""

from __future__ import annotations

from argparse import Namespace
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit


def _mock_kickoff_dependencies(monkeypatch, *, dry_run: bool):
    """Stub everything ``main.main()`` reaches into except the new MCP wiring.

    Yields the captured mocks so tests can assert against them.
    """
    import crew
    import main
    import mcp_servers
    import runtime

    monkeypatch.setattr(main, "parse_args", lambda: Namespace(verbose=False, dry_run=dry_run))
    monkeypatch.setattr(main, "check_env", lambda: None)
    monkeypatch.setattr(main, "dry_run_summary", lambda _crew: None)
    monkeypatch.setattr(runtime, "bind_run_id", lambda _run_id: None)

    fake_crew = MagicMock()
    fake_crew.kickoff = MagicMock(return_value=MagicMock(token_usage=None))
    fake_build_crew = MagicMock(return_value=fake_crew)
    monkeypatch.setattr(crew, "build_crew", fake_build_crew)

    sentinel_registry = MagicMock(name="provisioned_mcp_registry")
    fake_cm = MagicMock()
    fake_cm.__enter__ = MagicMock(return_value=sentinel_registry)
    fake_cm.__exit__ = MagicMock(return_value=None)
    fake_provisioned = MagicMock(return_value=fake_cm)
    monkeypatch.setattr(mcp_servers, "provisioned_mcp_tools", fake_provisioned)

    return {
        "build_crew": fake_build_crew,
        "crew": fake_crew,
        "provisioned": fake_provisioned,
        "cm": fake_cm,
        "sentinel_registry": sentinel_registry,
    }


class TestMainMCPDispatch:
    def test_dry_run_skips_mcp_provisioning(self, monkeypatch):
        """Dry-run path: ``provisioned_mcp_tools()`` is never entered.

        Pins the explicit dry-run skip in ``main.main()`` so a future
        refactor that accidentally re-routes dry-run through the CM
        (and thereby starts subprocesses on a preview run) gets caught.
        """
        import main

        mocks = _mock_kickoff_dependencies(monkeypatch, dry_run=True)

        main.main()

        # build_crew called once (for dry_run_summary) WITHOUT mcp_tools.
        mocks["build_crew"].assert_called_once_with(verbose=False)
        # provisioned_mcp_tools never invoked.
        mocks["provisioned"].assert_not_called()
        # kickoff not reached on the dry-run path.
        mocks["crew"].kickoff.assert_not_called()

    def test_normal_run_wraps_kickoff_in_provisioned_mcp_cm(self, monkeypatch):
        """Full run: kickoff lives inside the ``provisioned_mcp_tools()`` CM,
        and ``build_crew`` receives the registry the CM yielded.

        Pins the cybersquad-mcp skill's Rule 2 (no runtime MCP attach):
        MCPs are wired in *at build_crew() time*, so the kickoff must
        run with the same registry that ``provisioned_mcp_tools()``
        yielded - if a future refactor moved kickoff outside the CM,
        adapter teardown would race the agent's last tool call.
        """
        import main

        mocks = _mock_kickoff_dependencies(monkeypatch, dry_run=False)

        main.main()

        mocks["provisioned"].assert_called_once()
        mocks["cm"].__enter__.assert_called_once()
        mocks["cm"].__exit__.assert_called_once()
        mocks["build_crew"].assert_called_once_with(
            verbose=False, mcp_tools=mocks["sentinel_registry"]
        )
        mocks["crew"].kickoff.assert_called_once()
