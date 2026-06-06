"""
tests/squad/_contract_assertions.py - shared contract checks for every
squad member's typed-tool surface.

Each squad member declares ``schemas: dict[str, type[BaseModel]]`` on its
``MEMBER`` constant - the tool-name -> args_schema mapping that pins the
LLM-visible per-tool contract. Three contract guarantees apply to every
agent:

1. The mapping matches the live tool's ``args_schema`` (identity check).
2. Every field on every schema carries a non-empty ``Field(description=...)``.
3. Closed-world: every tool with a private (``_*``) args_schema class is in
   the mapping, and every mapping entry resolves to a registered tool.

The per-agent ``tests/squad/<agent>/test_args_schemas.py`` files parametrize
over ``MEMBER.schemas`` and call the helpers below, then add their own
agent-specific accept/reject cases. The contract logic lives in one place;
the per-agent data table stays at the per-agent layer.

This module is intentionally NOT named ``test_*.py`` - pytest does not
collect it, it is imported by the per-agent test files.
"""

from __future__ import annotations

from pydantic import BaseModel

from squad import SquadMember, SquadTool


def _tools_by_name(member: SquadMember) -> dict[str, SquadTool]:
    return {t.name: t for t in member.tools}


def assert_tool_wires_explicit_schema(member: SquadMember, tool_name: str) -> None:
    """Every entry in ``member.schemas`` matches the live tool's ``args_schema``."""
    tool_obj = _tools_by_name(member)[tool_name]
    expected = member.schemas[tool_name]
    assert tool_obj.args_schema is expected, (
        f"{tool_name} args_schema is {tool_obj.args_schema!r}; expected {expected!r}"
    )


def assert_field_descriptions_present(tool_name: str, schema_cls: type[BaseModel]) -> None:
    """Every field on the schema carries a non-empty ``Field(description=...)``."""
    for field_name, field_info in schema_cls.model_fields.items():
        desc = field_info.description
        assert desc, f"{tool_name}::{field_name} missing Field(description=...)"
        assert isinstance(desc, str) and desc.strip(), (
            f"{tool_name}::{field_name} description is blank"
        )


def assert_closed_world_mapping(member: SquadMember) -> None:
    """The schemas mapping covers every member-private args_schema class.

    Closed-world structural check: every tool whose Tool exposes a private
    (``_*``) args_schema class name is in ``member.schemas``; every entry
    in the mapping resolves to a registered tool. A new typed tool added
    without a schemas entry fires this test before reviewers see the PR.
    """
    tools = _tools_by_name(member)
    private_schema_tools = {
        name
        for name, t in tools.items()
        if getattr(getattr(t, "args_schema", None), "__name__", "").startswith("_")
    }
    assert private_schema_tools == set(member.schemas), (
        f"Mismatch between {member.slug} typed-tool wrappers and MEMBER.schemas: "
        f"in registry but not mapping = {private_schema_tools - set(member.schemas)}; "
        f"in mapping but not registry = {set(member.schemas) - private_schema_tools}"
    )
