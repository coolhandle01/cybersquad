"""
tests/test_squad_build_agent.py - covers the MCP-tool splice in ``build_agent``.

The invariant under test is the ``cybersquad-mcp`` skill's: the per-member
static tools come first, the crew-wide MCP tools are spliced on the end. It is
covered at two layers:

- **Unit** (``squad.Agent`` stubbed): the splice logic itself. No real CrewAI
  Agent, no LLM, no network - so it runs in the ``-m unit`` job and keeps
  ``build_agent``'s body covered.
- **Integration** (real Agent): confirms a real CrewAI Agent actually accepts
  the spliced tools. Constructing an Agent fires a telemetry span to
  telemetry.crewai.com - a network call - so these are marked ``integration``
  (out of the unit job), and ``_disable_crewai_telemetry`` gates the span.

Mocked, per-member agent-reasoning coverage is the broader job tracked in #121.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from crewai import LLM
from crewai.tools import tool

from squad import build_agent
from squad.programme_manager import MEMBER as PROGRAMME_MANAGER


@pytest.fixture(autouse=True)
def _disable_crewai_telemetry(monkeypatch):
    """Suppress CrewAI's construction-time telemetry span (a network call to
    telemetry.crewai.com). CrewAI re-reads these env vars on each check, so
    setting them before the Agent is built gates the call."""
    monkeypatch.setenv("CREWAI_DISABLE_TELEMETRY", "true")
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")


def _make_fake_mcp_tool(name: str):
    """Build a stand-in for a MCP-provisioned BaseTool.

    A MagicMock is rejected by Agent(tools=...) because Pydantic validates each
    tool against the BaseTool model. ``@crewai.tools.tool`` returns a concrete
    BaseTool subclass, so a no-op wrapped function suffices.
    """

    @tool(name)
    def _stub() -> str:
        """Stand-in MCP tool for build_agent splice tests."""
        return ""

    return _stub


@pytest.mark.unit
class TestBuildAgentSpliceUnit:
    """Splice logic with ``squad.Agent`` stubbed - no real Agent / LLM /
    telemetry. Asserts on the ``tools`` argument the factory hands to
    ``Agent(...)``, which is exactly what the splice produces, and keeps
    ``build_agent``'s body covered in the ``-m unit`` run."""

    @staticmethod
    def _capture_agent_kwargs(monkeypatch) -> dict:
        captured: dict = {}

        def fake_agent(**kwargs):
            captured.update(kwargs)
            return MagicMock()

        monkeypatch.setattr("squad.Agent", fake_agent)
        return captured

    def test_static_tools_first_then_crew_wide_mcp_tools(self, monkeypatch):
        """The tool list is ``[*member.tools, *crew_wide_mcp_tools]`` - the
        canonical typed surface opens the LLM-visible menu, MCP tools on the
        end."""
        captured = self._capture_agent_kwargs(monkeypatch)
        mcp_tool_a = _make_fake_mcp_tool("get_current_time")
        mcp_tool_b = _make_fake_mcp_tool("convert_time")

        build_agent(
            PROGRAMME_MANAGER,
            MagicMock(name="llm"),
            crew_wide_mcp_tools=[mcp_tool_a, mcp_tool_b],
        )

        tools = captured["tools"]
        assert list(tools[: len(PROGRAMME_MANAGER.tools)]) == list(PROGRAMME_MANAGER.tools)
        assert len(tools) == len(PROGRAMME_MANAGER.tools) + 2
        assert [tools[-2].name, tools[-1].name] == ["get_current_time", "convert_time"]

    def test_default_crew_wide_mcp_tools_is_empty(self, monkeypatch):
        """Omitting ``crew_wide_mcp_tools`` means the agent gets only the
        member's static tool registry - the no-MCP path used in the dry-run."""
        captured = self._capture_agent_kwargs(monkeypatch)

        build_agent(PROGRAMME_MANAGER, MagicMock(name="llm"))

        assert list(captured["tools"]) == list(PROGRAMME_MANAGER.tools)


@pytest.fixture
def real_llm() -> LLM:
    """A real LLM instance for the integration layer. Pydantic rejects a plain
    MagicMock for ``Agent(llm=...)`` because the field is typed ``str |
    BaseLLM``. Constructing the LLM makes no network call; only the Agent
    constructor would, and ``_disable_crewai_telemetry`` gates that. Scoped to
    the integration tests so the unit run constructs no real CrewAI objects."""
    return LLM(model="anthropic/claude-sonnet-4-20250514", temperature=0.0, max_tokens=1)


@pytest.mark.integration
class TestBuildAgentMCPSpliceIntegration:
    """A real CrewAI Agent accepts the spliced tools. This is the signal the
    unit layer cannot give: that CrewAI's Agent constructor validates our
    member.tools + MCP BaseTool shapes and preserves their order."""

    def test_static_tools_first_then_crew_wide_mcp_tools(self, real_llm):
        mcp_tool_a = _make_fake_mcp_tool("get_current_time")
        mcp_tool_b = _make_fake_mcp_tool("convert_time")

        agent = build_agent(
            PROGRAMME_MANAGER,
            real_llm,
            crew_wide_mcp_tools=[mcp_tool_a, mcp_tool_b],
        )

        assert len(agent.tools) == len(PROGRAMME_MANAGER.tools) + 2
        assert agent.tools[-2].name == "get_current_time"
        assert agent.tools[-1].name == "convert_time"

    def test_default_crew_wide_mcp_tools_is_empty(self, real_llm):
        agent = build_agent(PROGRAMME_MANAGER, real_llm)

        assert len(agent.tools) == len(PROGRAMME_MANAGER.tools)
