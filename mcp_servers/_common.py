"""
mcp_servers._common - Utilities shared across every provisioned MCP submodule.

The pre-flight check for the CrewAI adapter stack lives here because every
submodule's ``available()`` builds on it: if ``mcpadapt`` is missing,
*every* MCP would crash at ``MCPServerAdapter.__init__`` with the same
interactive ``click.confirm`` install prompt. Keeping the check at the
package root means each submodule's per-vendor availability check stays
narrow ("is this vendor's server module importable?") and the shared
"is the framework wiring usable at all?" answer is computed once.
"""

from __future__ import annotations

import importlib.util


def mcp_adapter_stack_usable() -> bool:
    """Return True iff CrewAI's MCP adapter stack is fully importable.

    ``mcpadapt`` ships under ``crewai-tools[mcp]``. Without it,
    ``MCPServerAdapter.__init__`` aborts with an interactive
    ``click.confirm`` install prompt - which in a non-TTY environment
    (CI, web session, daemon) crashes the host before our error path
    runs. Pre-checking lets us emit a *clear* warning naming the extra
    instead of letting CrewAI's interactive fallback fire.
    """
    return importlib.util.find_spec("mcpadapt") is not None
