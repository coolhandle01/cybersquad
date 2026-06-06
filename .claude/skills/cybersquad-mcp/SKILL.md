---
name: cybersquad-mcp
description: How cybersquad provisions and consumes Model Context Protocol servers. Build-time only, exact version pins, explicit tool allowlist, typed return models, audit logging. Designed around the MCP spec's "tool annotations are untrusted unless from a trusted server" rule and CrewAI's `MCPServerAdapter.__init__`-auto-starts behaviour. Load before editing any file under `mcp_servers/` or the MCP wiring in `crew.py`.
---

# MCP provisioning discipline

## The threat the discipline exists to defend against

The MCP spec (modelcontextprotocol/spec 2025-06-18, basic / Security and Trust & Safety) says it explicitly:

> Tools represent arbitrary code execution and must be treated with appropriate caution. ... Descriptions of tool behavior such as annotations should be considered untrusted, unless obtained from a trusted server.

CrewAI's own security guidance (`docs.crewai.com/en/mcp/security`) puts the timing more sharply:

> A malicious MCP server can craft its tool metadata (names, descriptions) to include hidden or overt instructions. ... This risk materializes simply by connecting and listing tools - you don't need to actually invoke them. The LLM processes this metadata as context, potentially compromising agent behavior.

Three implications shape every rule below:

1. **Provisioning is the attack surface, not just calling.** Once an adapter is started, the server's tool names + descriptions + JSON inputSchemas are in the agent's tool menu. CrewAI's `CrewAIMCPTool._generate_description` (see `crewai_tools/adapters/mcp_adapter.py`) concatenates the schema *into* the description, so a poisoned `inputSchema` is just as dangerous as a poisoned `description`.
2. **`MCPServerAdapter.__init__` auto-starts the subprocess.** It does not wait for `__enter__`. Construction is the side-effect window. Anywhere we materialise an adapter is a place a server's prose reaches the agent.
3. **The slow-boil variant.** A MCP that returns clean data for six months and drops a payload only when the consumer's context shows a specific programme handle. Static review never catches it. We design against it with build-time provisioning, exact pins, an explicit tool allowlist, typed returns, and audit logging.

## The five rules

### Rule 1 - Vendor package pinned EXACTLY; consumed through its typed models

Pin the vendor MCP package with `==` in `pyproject.toml` under `[project.optional-dependencies] mcp`. A minor / patch bump can re-word the tool's name, description, or inputSchema - which the spec marks untrusted - so a version bump is a review event. The skill upgrade ritual (see "Upgrading a vendor MCP" below) governs it.

Where the vendor publishes Pydantic models for tool returns (e.g. `mcp_server_time.server.TimeResult`), consume through them so `mypy` enforces the shape boundary. A return type of `Any` / `object` / `dict[str, Any]` on a consumed MCP tool is a contributor signal - treat it as any other linter finding, and if you cannot avoid it, leave a `FIXME` linking back here:

```python
# FIXME(cybersquad-mcp): <vendor> does not publish typed return models;
# narrow this to a local Pydantic model once we know the field set.
result: dict[str, Any] = call_mcp_tool(...)
```

Schemas catch *shape*. They do not catch *intent* - an exfil URL is a valid `str` and `model_validate` passes it cleanly. The shape contract is the first wall; the second is the input-edge symmetry already enforced by every `@cyber_tool` (see `cybersquad-tool` skill) and the prompt-injection-aware free-text fields in `models/` (see `cybersquad-models`). When a MCP return crosses into a wrapper that an agent will reason over, the free-text fields get the same treatment we give attacker-influenceable text from any other source.

### Rule 2 - No runtime MCP attach

`mcp_servers.provisioned_mcp_tools()` (the orchestrator in `mcp_servers/__init__.py`) is the only entry point; the actual `MCPServerAdapter` is constructed inside the per-MCP submodule's `enter(stack)` helper (e.g. `mcp_servers/_time.py:enter`). `crew.py` consumes the orchestrator's output; nothing else does.

```python
# wrong - runtime attach from inside a tool wrapper
@cyber_tool("attach_discovered_mcp", args_schema=AttachArgs)
def attach_discovered_mcp(url: str) -> ...:
    from crewai_tools import MCPServerAdapter  # NEVER
    adapter = MCPServerAdapter(...)
    ...

# correct - the URL is recorded as evidence; no adapter is constructed
@cyber_tool("record_discovered_mcp", args_schema=RecordArgs)
def record_discovered_mcp(url: str) -> DiscoveredMCP:
    return DiscoveredMCP(url=url, advertised_tools=..., evidence=...)
```

If a future test or contributor finds a path to materialise `MCPServerAdapter` outside `mcp_servers/`, that is a design bug. Fix the path; do not narrow the rule. If you are *certain* you need to materialise an adapter elsewhere and the user has accepted the risk, leave a `FIXME` and open an issue:

```python
# FIXME(cybersquad-mcp): out-of-band MCP attach for <reason>. This violates
# the build-time-only invariant; see issue #<n>. Do not extend this pattern.
```

### Rule 3 - Provisioned and discovered MCP sets stay disjoint

A MCP we *provisioned* for capability is never one we *probe*. A MCP we *discovered* in recon is never one we *attach* to. Two non-overlapping sets, enforced at `build_crew()`.

The good case: OSINT labels a discovered MCP server, VR has visibility on it via the workspace handoff, PT receives it as recon evidence and probes it through a dedicated MCP-attack tool (a sibling of `prompt_injection_tool`; future work behind #141 plus a `DiscoveredMCP` model). The MCP server's claimed tool inventory becomes the attack surface.

The bad case: any agent treating an in-the-wild MCP URL as something it can install on the fly. The build-time provisioning rule plus the workspace handoff for discovered MCPs keep the sets disjoint.

### Rule 4 - Explicit tool allowlist via `*tool_names`

`MCPServerAdapter(serverparams, *tool_names, connect_timeout=...)` accepts a positional allowlist of tool names. We always pass one. The allowlist is a module-private `_ALLOWED_TOOLS` tuple in each per-MCP submodule (e.g. `mcp_servers/_time.py`):

```python
_ALLOWED_TOOLS: tuple[str, ...] = ("get_current_time", "convert_time")
```

Why: a vendor version bump that adds a new tool would otherwise silently widen the agent's surface (see Rule 1's "version bump is a review event"). With the allowlist, the new tool only reaches the agent once a contributor extends the tuple - which makes it a reviewer's checkbox at the same time they re-vet the bump.

If you find yourself wanting to omit the allowlist ("just give the agent everything the server has"), you have lost the property the allowlist exists to provide. Either narrow what the agent actually needs and add only those names, or leave a `FIXME(cybersquad-mcp)` linking to the issue that argues for the broader surface.

### Rule 5 - Audit log on connection

Every provisioned MCP logs `MCP[<name>]: starting; allowed_tools=... connect_timeout=...` before construction and `MCP[<name>]: started; tools=[...]` after. Two lines, two purposes:

- **Pre-start "starting" line** - audit captures *intent* even if the adapter fails to start. If a poisoned server crashes the host during `__init__`, the operator still has the record of "we attempted to load tools X, Y, Z under timeout T".
- **Post-start "started" line** - audit captures what the server *actually exposed* under our filter. A name discrepancy between intent and resolved is a signal the server is doing something unexpected.

If you add a new provisioned MCP, mirror both lines via the `enter(stack)` helper in the new submodule (model: `mcp_servers/_time.py:enter`). Do not collapse to one log line - the failure mode the two-line pattern catches is exactly the one we care about.

## Wiring layout

```
mcp_servers/
├── __init__.py     # provisioned_mcp_tools() orchestrator + ProvisionedMCPTools registry
├── _common.py      # Shared utilities (e.g. mcp_adapter_stack_usable())
└── _<name>.py      # One submodule per provisioned MCP - shipped: _time.py
```

- **`mcp_servers/__init__.py`** - the orchestrator. `provisioned_mcp_tools()` is the context manager owning adapter lifecycles via `ExitStack`. Each enabled MCP's `enter(stack)` is called inside the manager; the stack runs each adapter's `stop()` in reverse on exit, including on exceptions.
- **`mcp_servers/_common.py`** - utilities shared across submodules. Today: `mcp_adapter_stack_usable()` pre-flight that prevents CrewAI's interactive `click.confirm` install fallback when `mcpadapt` is missing.
- **`mcp_servers/_<name>.py`** - one submodule per MCP. Each carries `_ALLOWED_TOOLS`, `_server_params()`, `available()`, and `enter(stack)`. Keeping each MCP in its own file means the file-skill loader auto-loads `cybersquad-mcp` on any submodule edit.
- **`crew.py`** - receives the `ProvisionedMCPTools` registry from `provisioned_mcp_tools()` and distributes it to agents via `build_agent(crew_wide_mcp_tools=...)`.
- **`main.py`** - wraps `crew.kickoff()` in `with provisioned_mcp_tools() as mcp_tools:`. Dry-run bypasses MCP startup (the agent menu is shown from a no-MCP build).
- **`config.py:MCPConfig`** - one `<name>_enabled` boolean per server, defaulting `false`; plus per-server settings (e.g. `time_timezone`) and the shared `connect_timeout_s` (default 10s, tighter than CrewAI's 30).

## Adding a new provisioned MCP

1. **Vet the vendor.** Source repository, maintainer, what other consumers depend on it. The MCP spec is permissive about server behaviour - the vetting is on us.
2. **Pin EXACTLY in `pyproject.toml`.** `mcp-server-time==2026.1.26`, not `>=`. Confirm the package publishes Pydantic models for tool returns; if not, see Rule 1's `FIXME` pattern.
3. **Add `<name>_enabled` to `MCPConfig`.** Default `false`. Add any per-server settings (timezone, endpoint, credentials).
4. **Create `mcp_servers/_<name>.py`.** Mirror `mcp_servers/_time.py`: module-private `_ALLOWED_TOOLS` tuple (justify each entry in a one-liner if not self-evident), `_server_params()`, `available()` (stack `mcp_adapter_stack_usable()` from `_common`), and `enter(stack)` with the two-line audit log.
5. **Register in the orchestrator.** Add `from . import _<name>` at the top of `mcp_servers/__init__.py` and an `if config.mcp.<name>_enabled: ...` branch inside `provisioned_mcp_tools()` mirroring the time MCP's. Update the warning's `missing` ternary if the same `mcp_adapter_stack_usable` check applies.
6. **Distribute in `crew.py`.** Crew-wide via `build_agent(crew_wide_mcp_tools=...)` is for genuinely cross-cutting capabilities (time, basic web search). Member-specific is the default - add a sibling field on `ProvisionedMCPTools` (e.g. `penetration_tester: tuple[BaseTool, ...]`) and route through `build_agent` only for the relevant member.
7. **Tests.** `tests/test_config.py::TestMCPConfig` for the env-var surface; `tests/test_mcp_servers.py` for the wiring (mocking `mcp_servers._<name>.MCPServerAdapter` and `mcp_servers._<name>.available`). The wiring tests should pin:
   - the allowlist passed to the adapter (`MCPServerAdapter.call_args.args`)
   - `connect_timeout` honoured
   - both audit log lines emitted
   - graceful skip-with-warning when the vendor package is not importable

## Upgrading a vendor MCP

Bumping a pinned vendor version is a review event because the spec marks tool prose untrusted:

1. Read the vendor's changelog / commit history between old and new versions, with focus on:
   - Renamed or added tools (allowlist needs updating?)
   - Re-worded tool descriptions (does the new prose still describe behaviour we want?)
   - inputSchema changes (CrewAI inlines the schema into the agent-facing description)
   - outputSchema changes (do our typed-model consumers still validate?)
2. Update the `==` pin in `pyproject.toml`.
3. If new tools are wanted, extend the submodule's `_ALLOWED_TOOLS`. If existing tools were renamed, update the tuple in lockstep with the pin.
4. Re-run the wiring tests. If the audit log's resolved tool names changed, that is the expected diff to review.
5. PR description must call out the prose diff in the vendor's tool definitions, not just "bump version".

## What this skill does not cover

- **Discovered-MCP probing.** Recon-side reasoning about advertised tool inventories, schema mismatches, and `object` returns is future work behind #141 plus a `DiscoveredMCP` model. This skill is only the provisioned side.
- **Remote transports (Streamable HTTP, SSE).** When we add a remote MCP, the spec requires OAuth 2.1 + RFC 8707 resource-bound tokens + PKCE + HTTPS-only + token-audience validation, and CrewAI's docs flag DNS rebinding for SSE servers - bind locals to `127.0.0.1`, never `0.0.0.0`. Until a remote MCP is on the wishlist, the only transport we support is stdio.
- **CrewAI's `mcps=` agent DSL.** CrewAI also supports `Agent(mcps=["url", "ref#tool"])` for inline MCP wiring. We deliberately use the `MCPServerAdapter` "advanced" path because the DSL hides lifecycle behind the agent constructor and would split the provisioning surface across multiple files - the build-time-only invariant becomes harder to enforce. If a future contributor proposes switching to the DSL, they need to show how the disjoint-set and audit-log rules survive.
- **The runtime skill story.** Whether the consuming agent needs a member-specialist runtime skill telling it about a newly-available tool is a separate decision (see `cybersquad-skill`). Small MCPs (time, misp) usually do not; large ones (playwright) usually do.

## Antipatterns - and when a FIXME is the honest answer

The bar is high. The skill exists to push back on these. If the user wants to land an antipattern anyway, the honest response is a `FIXME(cybersquad-mcp)` comment that links to the issue arguing for the exception, *not* a quiet capitulation.

| Antipattern | Push back this way |
|---|---|
| `MCPServerAdapter(...)` constructed outside a submodule of `mcp_servers/` | Rule 2. If the contributor is sure, `FIXME(cybersquad-mcp)` + issue link. |
| Loose `>=X.Y` pin on a vendor MCP package | Rule 1. The version bump is the review event; `>=` skips it. |
| Omitting `*tool_names` allowlist on `MCPServerAdapter(...)` | Rule 4. "Everything the server has" is the default attack surface. |
| `dict[str, Any]` return on a consumed MCP tool when the vendor publishes models | Rule 1. Use the vendor's model, or write a local one. |
| `dict[str, Any]` return when the vendor does NOT publish models | Rule 1's `FIXME` pattern - file the schema gap as a follow-up. |
| Defaulting `<name>_enabled=True` in `MCPConfig` | Fresh-checkout safety. The vendor package may not be installed. |
| Catching `MCPServerAdapter(...)` exceptions to silently fall through | Log a warning and skip (the missing-vendor pattern), or let it propagate. Never silent. |
| One log line instead of "starting" + "started" | Rule 5. The pre-start line is what catches a poisoned `__init__`. |
| Re-using a discovered MCP URL via `MCPServerAdapter` | Rule 3. Provisioned vs. discovered sets must stay disjoint. |
| Reasoning over a MCP tool's `description` field in cybersquad docs / prompts | The prose is attacker-influenceable. If you cite it, paraphrase from behaviour you have verified, not from the vendor's string. |

## Upstream alignment

- [MCP spec 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18) - the protocol, with Security and Trust & Safety the canonical source for the rules above. Particularly the "tool annotations untrusted unless from a trusted server" and "explicit user consent before invoking any tool" requirements (`MUST`).
- [CrewAI MCP overview](https://docs.crewai.com/en/mcp/overview) / [security](https://docs.crewai.com/en/mcp/security) / [stdio](https://docs.crewai.com/en/mcp/stdio) - the framework wrappers we provision through. Note CrewAI's `MCPServerAdapter` starts the server in `__init__`, not in `__enter__`.
- `crewai_tools/adapters/mcp_adapter.py` - shipped source, definitive over docs. `CrewAIMCPTool._generate_description` is where the vendor's inputSchema gets concatenated into the agent-facing description.
- #144 - the MCP wishlist + threat-model comment this skill codifies.
- #146 - the input-edge symmetry. `args_schema` on every wrapper prevents the LLM from mis-calling our tools. This skill is the symmetric *return* edge for tools we consume.
- #141 - sanitisation of attacker-influenceable text crossing into agent context. Schemas catch shape; #141 catches intent.
- `cybersquad-models` skill - the prompt-injection-aware free-text field pattern that MCP returns inherit when their data crosses into an agent-reasoning surface.
- `cybersquad-tool` skill - the `args_schema` + scope-typed-input discipline this skill is symmetric to.

## When this skill fires

Auto-loads on edits to:

- Any file under `mcp_servers/` - the provisioning package (orchestrator, shared utilities, per-MCP submodules)
- `crew.py` - where MCP tools are distributed to agents (stacks on `cybersquad-agent-llm`)
