"""
mcp_servers._time - The time MCP.

Vendor: the official ``mcp-server-time`` server from the Anthropic
reference set, source at
https://github.com/modelcontextprotocol/servers/tree/main/src/time and
published to PyPI as ``mcp-server-time`` (pinned exact in
``pyproject.toml``'s ``[project.optional-dependencies] mcp`` block).
Exposes ``get_current_time`` and ``convert_time``; we allowlist both
explicitly via ``_ALLOWED_TOOLS``.

Submodule template for every provisioned MCP. Carries:

  - ``_ALLOWED_TOOLS``  - explicit allowlist tuple (Rule 4 in the
    cybersquad-mcp skill). A vendor version bump that adds a new tool
    does not silently widen the agent's surface; extending this tuple
    is the review event by construction.
  - ``_server_params()`` - the ``StdioServerParameters`` builder. Stdio
    is the only transport supported today; remote MCPs (Streamable HTTP,
    SSE) live behind future work in the skill.
  - ``available()``     - per-vendor availability check, stacked on the
    shared ``mcp_adapter_stack_usable()``. Mirrors the missing-binary
    pattern in ``tools/pentest/*`` (gitleaks, testssl).
  - ``enter(stack)``    - the materialisation helper. Logs intent
    *before* ``MCPServerAdapter`` construction (which is the side-effect
    window - the subprocess starts inside ``__init__``) and the resolved
    tool names *after* enter, so audit trail captures both even on
    construction failure.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from collections.abc import Sequence
from contextlib import ExitStack

from crewai.tools import BaseTool
from crewai_tools import MCPServerAdapter
from mcp import StdioServerParameters

from config import config

from ._common import mcp_adapter_stack_usable

logger = logging.getLogger(__name__)

# Explicit allowlist passed as ``*tool_names`` to the adapter. Documented
# in the cybersquad-mcp skill's upgrade ritual: a vendor version bump that
# adds a new tool must extend this tuple in the same PR, after re-vetting
# the new tool's prose (name, description, inputSchema).
_ALLOWED_TOOLS: tuple[str, ...] = ("get_current_time", "convert_time")


def _server_params() -> StdioServerParameters:
    """``StdioServerParameters`` for ``python -m mcp_server_time``.

    Invoked via ``sys.executable`` so the server runs under the same
    interpreter the rest of the squad uses (rather than whatever
    ``python`` resolves to on PATH).
    """
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_server_time", "--local-timezone", config.mcp.time_timezone],
    )


def available() -> bool:
    """True iff the time MCP can actually be started.

    Requires both the vendor server module (``mcp_server_time``) and the
    CrewAI MCP adapter stack (``mcpadapt`` via ``crewai-tools[mcp]``).
    If anything is missing the package-level warning fires and the
    server is skipped, mirroring the missing-binary pattern.
    """
    return mcp_adapter_stack_usable() and importlib.util.find_spec("mcp_server_time") is not None


def enter(stack: ExitStack) -> Sequence[BaseTool]:
    """Materialise and start the time MCP, returning its allowed tool list.

    ``MCPServerAdapter.__init__`` starts the subprocess - construction
    is the side-effect window. We log the declared allowlist *before*
    construction (so the audit trail captures intent even on a start
    failure), then log the resolved tool names after a successful enter
    (so audit captures what the server actually exposed under our
    filter).
    """
    logger.info(
        "MCP[time]: starting; allowed_tools=%s connect_timeout=%ds",
        _ALLOWED_TOOLS,
        config.mcp.connect_timeout_s,
    )
    adapter = MCPServerAdapter(
        _server_params(),
        *_ALLOWED_TOOLS,
        connect_timeout=config.mcp.connect_timeout_s,
    )
    tools = stack.enter_context(adapter)
    logger.info("MCP[time]: started; tools=%s", [t.name for t in tools])
    return tools
