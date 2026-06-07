"""
tests/test_crew.py - covers the MCP-tool distribution path added by #144.

The rest of ``build_crew()`` (LLM construction, memory wiring, task
context chaining) is exercised end-to-end by the BDD tests and the
``--dry-run`` smoke path in CI; this file pins the small invariant the
``cybersquad-mcp`` skill cares about: provisioned-MCP tools are passed
to every member's ``build_agent`` via the ``crew_wide_mcp_tools`` kwarg,
or an empty tuple when no ``ProvisionedMCPTools`` registry is supplied.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit


def _wire_build_crew_mocks(monkeypatch, captured: dict[str, tuple]) -> None:
    """Stub the heavy dependencies of ``crew.build_crew`` so the only thing
    actually exercised is the MCP-tool distribution branch.

    ``build_agent`` records the ``crew_wide_mcp_tools`` it received per
    member; ``_build_llm`` / ``_build_long_term_memory`` / ``build_tasks``
    / ``Crew`` are stubbed away so the test does not touch CrewAI's real
    constructors.
    """
    import crew

    def fake_build_agent(member, llm, verbose, crew_wide_mcp_tools=()):
        captured[member.slug] = tuple(crew_wide_mcp_tools)
        return MagicMock()

    monkeypatch.setattr(crew, "build_agent", fake_build_agent)
    monkeypatch.setattr(crew, "_build_llm", lambda: MagicMock())
    monkeypatch.setattr(crew, "_build_long_term_memory", lambda: False)
    monkeypatch.setattr(crew, "build_tasks", lambda _agents_by_slug: [])
    monkeypatch.setattr(crew, "Crew", MagicMock())


class TestBuildCrewMCPDistribution:
    def test_no_mcp_tools_means_empty_crew_wide_for_every_member(self, monkeypatch):
        """Default ``mcp_tools=None`` resolves to an empty tuple at the splat,
        and every member's ``build_agent`` sees ``crew_wide_mcp_tools=()``."""
        import crew

        captured: dict[str, tuple] = {}
        _wire_build_crew_mocks(monkeypatch, captured)

        crew._assemble_crew()

        # All six members got an empty crew-wide MCP tuple.
        assert captured, "expected build_agent to be called for at least one member"
        assert all(extras == () for extras in captured.values())

    def test_provisioned_mcp_tools_distribute_crew_wide_to_every_member(self, monkeypatch):
        """``ProvisionedMCPTools.crew_wide`` is the only injection point for
        MCP-sourced tools (Rule 2 of cybersquad-mcp). Every member's
        ``build_agent`` gets the same tuple - confirmed by sampling all
        captured calls."""
        import crew
        from mcp_servers import ProvisionedMCPTools

        captured: dict[str, tuple] = {}
        _wire_build_crew_mocks(monkeypatch, captured)

        fake_tool = MagicMock()
        fake_tool.name = "get_current_time"
        registry = ProvisionedMCPTools(crew_wide=(fake_tool,))

        crew._assemble_crew(mcp_tools=registry)

        assert captured, "expected build_agent to be called for at least one member"
        for slug, extras in captured.items():
            assert extras == (fake_tool,), f"member {slug!r} did not receive the MCP tool"

    def test_build_crew_forwards_resolved_output_log_file(self, monkeypatch):
        """``_assemble_crew`` passes ``_resolve_output_log_file()``'s value
        straight through to ``Crew(output_log_file=...)`` (#167)."""
        import crew

        captured: dict[str, tuple] = {}
        _wire_build_crew_mocks(monkeypatch, captured)
        monkeypatch.setattr(crew, "_resolve_output_log_file", lambda: "/runs/r1/crew.log")

        crew._assemble_crew()

        _, kwargs = crew.Crew.call_args
        assert kwargs["output_log_file"] == "/runs/r1/crew.log"


class TestResolveOutputLogFile:
    """``_resolve_output_log_file`` keys on ``run_id`` alone (not the
    per-programme ``run_dir()``) so it resolves at ``build_crew()`` time, before
    the PM binds ``programme_handle`` mid-run - see #167."""

    def test_returns_run_scoped_path_and_creates_parent(self, monkeypatch, tmp_path):
        import crew

        monkeypatch.setattr(crew.config, "output_log_enabled", True)
        monkeypatch.setattr(crew.config, "reports_dir", str(tmp_path))
        monkeypatch.setattr("runtime.run_id", "20260531-000000-abc123")

        result = crew._resolve_output_log_file()

        expected = tmp_path / "20260531-000000-abc123" / "crew.log"
        assert result == str(expected)
        # Parent created eagerly: CrewAI's FileHandler appends without mkdir,
        # and the first write lands before any tool makes the run folder.
        assert expected.parent.is_dir()

    def test_returns_none_when_disabled(self, monkeypatch, tmp_path):
        import crew

        monkeypatch.setattr(crew.config, "output_log_enabled", False)
        monkeypatch.setattr(crew.config, "reports_dir", str(tmp_path))
        monkeypatch.setattr("runtime.run_id", "run-1")

        assert crew._resolve_output_log_file() is None
        assert not (tmp_path / "run-1").exists()

    def test_returns_none_when_no_run_bound(self, monkeypatch, tmp_path):
        """Dry-run path: ``build_crew`` runs without ``bind_run_id``, so
        ``runtime.run_id`` is empty and no log is wired."""
        import crew

        monkeypatch.setattr(crew.config, "output_log_enabled", True)
        monkeypatch.setattr(crew.config, "reports_dir", str(tmp_path))
        monkeypatch.setattr("runtime.run_id", "")

        assert crew._resolve_output_log_file() is None


class TestBuildLongTermMemory:
    """``_build_long_term_memory`` returns CrewAI's disabled value ``False``
    (not ``None`` - ``Crew.memory`` defaults to ``False`` and its telemetry
    rejects ``None``) when long-term memory is off."""

    def test_returns_false_when_disabled(self, monkeypatch) -> None:
        import crew

        monkeypatch.setattr(crew.config.memory, "long_term_enabled", False)
        assert crew._build_long_term_memory() is False


class TestBuildCrew:
    """``build_crew`` is the single seam that opens the provisioned-MCP scope and
    yields a ready crew (assembled by ``_assemble_crew``). Pins the
    ``cybersquad-mcp`` skill's Rule 2 (build-time provisioning): it always opens
    the CM and keeps it open for the block. Dry-run is about not executing tasks,
    not about skipping provisioning, so it provisions the same way.
    """

    def test_opens_cm_and_passes_registry(self, monkeypatch) -> None:
        import crew

        fake_crew = MagicMock(name="crew")
        fake_assemble = MagicMock(return_value=fake_crew)
        sentinel_registry = MagicMock(name="provisioned_mcp_registry")
        fake_cm = MagicMock()
        fake_cm.__enter__ = MagicMock(return_value=sentinel_registry)
        fake_cm.__exit__ = MagicMock(return_value=None)
        fake_provisioned = MagicMock(return_value=fake_cm)
        monkeypatch.setattr(crew, "_assemble_crew", fake_assemble)
        monkeypatch.setattr(crew, "provisioned_mcp_tools", fake_provisioned)

        with crew.build_crew(verbose=False) as built:
            assert built is fake_crew
            # CM is open across the block - teardown has not run yet.
            fake_cm.__exit__.assert_not_called()

        fake_provisioned.assert_called_once()
        fake_cm.__enter__.assert_called_once()
        fake_cm.__exit__.assert_called_once()
        fake_assemble.assert_called_once_with(verbose=False, mcp_tools=sentinel_registry)
