"""
squad/__init__.py - shared SquadMember dataclass + agent/task builders.

Each sub-package declares one module-level ``MEMBER = SquadMember(...)`` constant.
Agent prose lives in three markdown files alongside it:

    role.md   goal.md   backstory.md

Task-specific prose lives in named subdirectories:

    <task_name>/description.md    <task_name>/expected_output.md

A squad member that appears in more than one pipeline task (e.g. the
Vulnerability Researcher runs as both attack-planner and findings-triager)
has one subdir per task:

    research/description.md   triage/description.md

Member-specialist skills live alongside the prose in a ``skills/`` subdirectory;
each skill is its own folder containing a ``SKILL.md`` with frontmatter, per the
crewai.skills loader contract. Squad-wide skills live at ``squad/skills/`` and
are attached at Crew construction in crew.py.

Assembly (LLM wiring, pipeline order, approval gates) lives in crew.py / tasks.py.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, cast, runtime_checkable

from crewai import LLM, Agent, Task
from crewai.tools import BaseTool, tool
from pydantic import BaseModel

SQUAD_SKILLS_DIR = Path(__file__).parent / "skills"


@runtime_checkable
class SquadTool(Protocol):
    """The shape every ``MEMBER.tools`` entry conforms to.

    Project-specific name (rather than e.g. ``CrewAITool``) so the squad's
    public surface stays decoupled from the underlying agent framework:
    today this Protocol matches the runtime shape ``crewai.tools.tool``
    produces, but the registry is "the tools the bounty squad uses", not
    "the tools CrewAI happens to produce". The Protocol stays a real
    abstraction: ``SquadMember.tools: list[SquadTool]`` and the specialist
    Protocols (``_PentestTool``, ``_ResearchBriefTool``) inherit from it
    so the cross-agent contract test in
    ``tests/test_squad_tool_contracts.py`` has a typed handle to walk.

    The decorators in use - the bare ``@tool``, ``@cyber_tool``,
    ``@pentest_tool``, ``@research_brief_tool`` - all produce CrewAI
    ``Tool`` instances that carry ``name``, ``description``, ``func``,
    and ``args_schema``. ``args_schema`` is part of the Protocol because
    every cybersquad wrapper carries an explicit Pydantic schema; the
    contract tests in ``tests/squad/<agent>/test_args_schemas.py`` walk
    it on every registered tool. ``func`` is declared via ``@property``
    (rather than as a plain class attribute) so the Protocol is
    satisfied by CrewAI's ``Tool`` model - its ``func`` field is typed
    ``Callable[P, R | Awaitable[R]]`` for the concrete wrapped function
    and would otherwise fail Protocol variance against
    ``Callable[..., object]``.
    """

    name: str
    description: str
    args_schema: type[BaseModel]

    @property
    def func(self) -> Callable[..., object]: ...


def cyber_tool(
    name: str,
    *,
    args_schema: type[BaseModel],
) -> Callable[[Callable[..., object]], SquadTool]:
    """The blessed cybersquad replacement for bare ``@crewai.tools.tool``.

    Equivalent to ``tool(name)`` except that ``args_schema`` is keyword-
    required: the explicit Pydantic class overrides the signature-inferred
    schema CrewAI would otherwise build. Every cybersquad ``@tool``
    wrapper carries one - the inferred path is not reachable anywhere
    in the squad. Per-field ``Field(description=...)`` is the targeting
    guidance the agent reads when picking the tool.

    Scope safety is a Pydantic-native property of the args_schema, not
    of this decorator: agent-facing target fields are typed via the
    ``TargetFQDNs`` / ``TargetEndpoints`` (list, filter) or
    ``TargetFQDN`` / ``TargetEndpoint`` (single, reject) aliases
    in ``tools.recon.scope``. The ``AfterValidator`` on each alias
    consults ``current_programme()`` during
    ``args_schema.model_validate(...)`` - CrewAI's tool-call path runs
    that validation before the wrapper body sees any input. The type
    IS the contract; there is no wrapper-side guard to forget.
    """

    def decorator(fn: Callable[..., object]) -> SquadTool:
        wrapped = tool(name)(fn)
        wrapped.args_schema = args_schema
        return cast(SquadTool, wrapped)

    return decorator


# Shared workspace wrappers are imported after ``cyber_tool`` is defined,
# because ``squad/tools/workspace_tools.py`` decorates with ``@cyber_tool`` and
# would hit a circular import if pulled in alongside the top-of-module
# imports. The deferred-import pattern is explicitly endorsed by ruff for
# this case: https://docs.astral.sh/ruff/rules/module-import-not-at-top-of-file/
from squad.tools.workspace_tools import (  # noqa: E402 - deferred to break import cycle (see comment above)
    read_attack_forest_tool,
    read_run_file_tool,
    read_run_filelist_tool,
)


@dataclass(frozen=True)
class SquadMember:
    """A single Bounty Squad member: identity, tools, and prose location.

    ``slug`` is derived from ``dir.name`` rather than stored separately - the
    two were always required to match (the dir name is the package path on
    disk) so the explicit field was just a place to introduce inconsistency.
    """

    dir: Path
    tools: list[SquadTool] = field(default_factory=list)
    # tool-name -> explicit Pydantic args_schema class. Populated alongside
    # ``tools`` so each member's typed-tool contract lives next to the
    # registry it describes; the closed-world cross-agent contract test in
    # ``tests/squad/test_args_schemas.py`` walks every member's schemas.
    schemas: dict[str, type[BaseModel]] = field(default_factory=dict)

    @property
    def slug(self) -> str:
        """Snake-case identifier (the on-disk package name)."""
        return self.dir.name

    def read(self, *parts: str) -> str:
        """Read a markdown file under this member's directory.

        read("role")                   -> <dir>/role.md
        read("triage", "description")  -> <dir>/triage/description.md
        """
        return (self.dir.joinpath(*parts).with_suffix(".md")).read_text(encoding="utf-8").strip()

    @property
    def skills_dir(self) -> Path:
        """Directory containing this member's specialist SKILL.md folders."""
        return self.dir / "skills"


def build_agent(
    member: SquadMember,
    llm: LLM,
    verbose: bool = False,
    crew_wide_mcp_tools: Sequence[BaseTool] = (),
) -> Agent:
    """Construct a CrewAI Agent from the member's role/goal/backstory files.

    Member-specialist skills are passed as a directory path; crewai.skills
    discovers each ``SKILL.md`` subfolder and loads at METADATA disclosure
    (frontmatter only) so the agent sees a cheap menu of what is available
    and pays the body cost only on activation. Squad-wide skills are merged
    in at Crew construction (crew.py) so they are discovered once per run.

    ``crew_wide_mcp_tools`` is the *only* injection point for
    provisioned-MCP tools. Per the ``cybersquad-mcp`` skill (Rule 2 - no
    runtime MCP attach), MCP tools come exclusively from
    ``mcp_servers.provisioned_mcp_tools()`` and are wired in here at
    ``build_crew()`` time. The list is appended to ``member.tools`` so
    the per-member typed registry stays authoritative for the
    cybersquad-side contract tests; MCP tools come from a third-party
    adapter and live outside the ``SquadTool`` Protocol surface by
    design.
    """
    skills: list[Path] = [member.skills_dir] if member.skills_dir.is_dir() else []
    # Static, contract-tested tools first; provisioned-MCP tools spliced
    # on the end. The order is observable in the LLM-visible tool menu -
    # the agent's canonical typed surface opens the menu, MCP-sourced
    # tools sit after as opaque BaseTool instances (per the discipline
    # in the cybersquad-mcp skill, see also #144 and #141).
    #
    # No explicit `list[BaseTool]` annotation here: `member.tools` is
    # `list[SquadTool]` - a Protocol that BaseTool satisfies structurally
    # - but `list[...]` is invariant so mypy cannot reconcile the splat
    # against a concrete `list[BaseTool]` literal. The runtime contract
    # (Agent(tools=...) accepts BaseTool) is the same either way.
    agent_tools = [*member.tools, *crew_wide_mcp_tools]
    return Agent(
        role=member.read("role"),
        goal=member.read("goal"),
        backstory=member.read("backstory"),
        tools=agent_tools,
        skills=skills,
        allow_delegation=False,
        llm=llm,
        verbose=verbose,
    )


def build_task(
    task_name: str,
    member: SquadMember,
    agent: Agent,
    context: list[Task] | None = None,
    human_input: bool = False,
) -> Task:
    """Create a Task from the member's task-specific prose files.

    Reads description and expected_output from ``<member.dir>/<task_name>/``.
    """
    return Task(
        description=member.read(task_name, "description"),
        expected_output=member.read(task_name, "expected_output"),
        agent=agent,
        context=context or [],
        human_input=human_input,
    )


__all__ = [
    "SquadMember",
    "SquadTool",
    "build_agent",
    "build_task",
    "cyber_tool",
    "read_attack_forest_tool",
    "read_run_file_tool",
    "read_run_filelist_tool",
]
