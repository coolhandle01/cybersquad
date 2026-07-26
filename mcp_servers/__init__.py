"""
mcp_servers - The provisioned MCP set, wired in at `build_crew()` time.

Per the `cybersquad-mcp` contributor skill, MCPs are attached at construction
time only. ``provisioned_mcp_tools()`` is the one place an
``MCPServerAdapter`` is materialised; the rest of the squad consumes the
tool list it yields. The companion rule is that *discovered* MCPs (URLs
the OSINT Analyst surfaces during a run) never come back through here -
they are recorded as evidence and probed through the dedicated MCP-attack
tool, not attached.

Three properties of CrewAI's adapter shape the design and are load-bearing
for the skill:

  1. ``MCPServerAdapter.__init__`` auto-starts the subprocess (it does not
     wait for ``__enter__``). Construction is the side-effect window -
     anywhere we materialise an adapter is a place a poisoned server can
     reach the agent's prompt menu just by being listed.
  2. The adapter accepts ``*tool_names`` as an allowlist filter. We pass
     every provisioned MCP's tools explicitly so a vendor adding a new
     tool in a version bump does not silently widen the agent's surface.
  3. ``connect_timeout`` is configurable (CrewAI default 30s). We tighten
     to ``config.mcp.connect_timeout_s`` so a hung subprocess does not
     stall the pipeline.

Adapter lifecycle is owned by an ``ExitStack`` inside the context manager:
each enabled MCP enters the stack on ``__enter__`` and its ``stop()`` runs
in reverse on ``__exit__``. ``main.py`` wraps ``crew.kickoff()`` in the
manager so subprocesses are torn down even on KeyboardInterrupt / crash.

Each MCP has a boolean in ``config.mcp``. Defaults are ``false`` so a fresh
checkout does not start subprocesses; flip them on after installing the
vendor package via ``pip install -e .[mcp]`` (pins are exact - see the
``[project.optional-dependencies] mcp`` block in ``pyproject.toml``).

Layout:

  ``mcp_servers/__init__.py`` - the public surface (``ProvisionedMCPTools``
      registry, ``provisioned_mcp_tools()`` context-manager orchestrator).
  ``mcp_servers/_common.py``  - utilities shared across every MCP
      submodule (today: the adapter-stack availability pre-flight that
      prevents CrewAI's interactive ``click.confirm`` install fallback).
  ``mcp_servers/_<name>.py``  - one submodule per provisioned MCP. Each
      carries its allowlist tuple, ``StdioServerParameters`` builder,
      availability check, and the ``enter(stack)`` helper that performs
      the adapter materialisation + two-line audit log. ``_time.py`` is
      the shipped example.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field

from crewai.tools import BaseTool

from config import config

from . import _time
from ._common import mcp_adapter_stack_usable

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProvisionedMCPTools:
    """The MCP-sourced tools the crew was provisioned with.

    ``crew_wide`` is the list distributed to every agent via
    ``build_agent(crew_wide_mcp_tools=...)``. Member-specific MCP tool
    lists would live as sibling fields here (e.g. ``penetration_tester``)
    when the first non-cross-cutting MCP arrives.

    The class is frozen so a consumer cannot mutate the list in place;
    a `tuple` (not list) is the canonical immutable carrier.
    """

    crew_wide: tuple[BaseTool, ...] = field(default_factory=tuple)


@contextmanager
def provisioned_mcp_tools() -> Iterator[ProvisionedMCPTools]:
    """Construct and run the squad's MCP servers for the lifetime of the block.

    ``main.py`` wraps the entire ``crew.kickoff()`` in this manager.
    Dry-run intentionally bypasses it - the agent menu is shown from a
    no-MCP build so dry-run does not start subprocesses.

    Each enabled MCP's ``enter(stack)`` connects its server (via
    ``MCPServerAdapter`` registered with the ``ExitStack``) and returns
    its allowed tool list. The stack runs each ``__exit__`` in reverse
    on the way out, including on exceptions, so a server that fails to
    start during the loop still triggers cleanup for the ones that did.
    """
    crew_wide: list[BaseTool] = []
    with ExitStack() as stack:
        if config.mcp.time_enabled:
            if _time.available():
                crew_wide.extend(_time.enter(stack))
            else:
                missing = "mcpadapt" if not mcp_adapter_stack_usable() else "mcp_server_time"
                logger.warning(
                    "CYBERSQUAD_MCP_TIME_ENABLED=true but %s is not importable; skipping. "
                    "Install via `pip install -e .[mcp]` (pulls in crewai-tools[mcp] "
                    "and mcp-server-time at the pinned versions) or set "
                    "CYBERSQUAD_MCP_TIME_ENABLED=false.",
                    missing,
                )
        yield ProvisionedMCPTools(crew_wide=tuple(crew_wide))


__all__ = ["ProvisionedMCPTools", "provisioned_mcp_tools"]
