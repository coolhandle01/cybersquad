"""
tests/test_squad_tool_contracts.py - contract test that walks every
``MEMBER.tools`` entry across the squad and asserts each ``@tool``-wrapped
function returns a pydantic ``BaseModel`` subclass or ``list[BaseModel]``.

The rule is the one the ``cybersquad-tool`` skill prescribes: returning a
bare ``dict`` or ``list[dict]`` strips the schema the agent should be
reading. The exception is ``finalise_X`` / ``save_X`` workspace-handle
tools that return the filename as ``str`` - those are whitelisted by name.

Why this lives in CI rather than mypy: the typed annotation is enforced at
runtime against the runtime registry of every ``SquadMember.tools`` entry.
A new tool with the wrong return type fails this test in the same PR that
introduces it, before any downstream agent sees the half-typed contract.
"""

from __future__ import annotations

import types
import typing
from typing import Union, get_args, get_origin

import pytest
from pydantic import BaseModel

from squad import SquadTool
from squad.disclosure_coordinator import MEMBER as DISCLOSURE_COORDINATOR
from squad.osint_analyst import MEMBER as OSINT_ANALYST
from squad.penetration_tester import MEMBER as PENETRATION_TESTER
from squad.programme_manager import MEMBER as PROGRAMME_MANAGER
from squad.technical_author import MEMBER as TECHNICAL_AUTHOR
from squad.vulnerability_researcher import MEMBER as VULNERABILITY_RESEARCHER

pytestmark = pytest.mark.unit


# Tools that intentionally return a workspace-handle string (the filename
# the next agent passes to a typed reader). The cybersquad-tool skill spells
# out why these stay as ``str`` rather than wrapping a ``WorkspaceHandle``
# model: the filename IS the handle, and the typed reader is the contract.
_HANDLE_TOOLS: frozenset[str] = frozenset(
    {
        "Run Initial Sweep",
        "Finalise Recon",
        "Finalise Research",
        "Finalise Triage",
        "Finalise Reports",
        "Save Findings",
        "Save Selected Programme",
    }
)


def _every_tool() -> list[tuple[str, SquadTool]]:
    """Flat list of (agent_slug, tool) pairs across every squad member."""
    out: list[tuple[str, SquadTool]] = []
    for member in (
        PROGRAMME_MANAGER,
        OSINT_ANALYST,
        PENETRATION_TESTER,
        VULNERABILITY_RESEARCHER,
        TECHNICAL_AUTHOR,
        DISCLOSURE_COORDINATOR,
    ):
        for tool_obj in member.tools:
            out.append((member.slug, tool_obj))
    return out


def _unwrap_optional(annotation: object) -> object:
    """Strip a trailing ``| None`` so the inner type is what gets checked.

    A lookup tool that returns ``Model | None`` (None as the documented
    miss / not-found sentinel - e.g. ``Lookup RDAP for ASN`` when the
    bootstrap registry has no entry for the ASN) is still typed: the
    schema the agent reads on a hit is the inner model. Only the literal
    ``None``-union is unwrapped; a two-real-type union (``A | B``) is left
    intact so it falls through to the failure path. ``dict | None`` also
    falls through - the inner ``dict`` is not a model.
    """
    if get_origin(annotation) in (Union, types.UnionType):
        non_none = [a for a in get_args(annotation) if a is not type(None)]
        if len(non_none) == 1:
            return non_none[0]
    return annotation


def _is_pydantic_model(annotation: object) -> bool:
    return isinstance(annotation, type) and issubclass(annotation, BaseModel)


def _is_list_of_pydantic(annotation: object) -> bool:
    origin = get_origin(annotation)
    if origin is not list:
        return False
    args = get_args(annotation)
    return len(args) == 1 and _is_pydantic_model(args[0])


def _is_whitelisted_handle(tool_obj: SquadTool, return_annotation: object) -> bool:
    """Workspace-handle ``str`` returns are allowed for the named tools."""
    return tool_obj.name in _HANDLE_TOOLS and return_annotation is str


def _is_list_of_strings(annotation: object) -> bool:
    """list[str] is permitted for flat handle / hostname lists.

    The Recon Subdomains tool returns a bare hostname list and the cert
    transparency / historical URL tools return hostname lists too - there
    is no schema beyond ``str`` to enforce here.
    """
    origin = get_origin(annotation)
    if origin is not list:
        return False
    args = get_args(annotation)
    return len(args) == 1 and args[0] is str


def _is_primitive(annotation: object) -> bool:
    """float (CVSS), int, bool are allowed for scalar-result tools."""
    return annotation in (float, int, bool)


class TestSquadToolContracts:
    @pytest.mark.parametrize(
        ("agent_slug", "tool_obj"),
        _every_tool(),
        ids=[f"{slug}::{t.name}" for slug, t in _every_tool()],
    )
    def test_tool_return_annotation_is_typed(self, agent_slug: str, tool_obj: SquadTool) -> None:
        """Every tool returns a BaseModel, a list[BaseModel], or a whitelisted
        primitive. ``dict``, ``list[dict]``, ``list[Any]``, bare ``list`` all
        fail."""
        hints = typing.get_type_hints(tool_obj.func)
        assert "return" in hints, f"{agent_slug}::{tool_obj.name} has no return annotation"
        # A documented ``Model | None`` miss sentinel is still typed - check
        # the inner type. ``dict | None`` and ``A | B`` fall through.
        ret = _unwrap_optional(hints["return"])

        if _is_pydantic_model(ret):
            return
        if _is_list_of_pydantic(ret):
            return
        if _is_whitelisted_handle(tool_obj, ret):
            return
        if _is_list_of_strings(ret):
            return
        if _is_primitive(ret):
            return

        pytest.fail(
            f"{agent_slug}::{tool_obj.name} returns {ret!r}; "
            "must be a pydantic BaseModel, list[BaseModel], list[str], "
            "a primitive, or a whitelisted workspace-handle str."
        )

    def test_squad_member_tools_is_typed_list(self) -> None:
        """``SquadMember.tools`` carries a typed list, not ``list[Any]``.

        The runtime check is intentionally minimal - the dataclass field
        is statically ``list[SquadTool]``, so this asserts the Protocol
        is satisfied by every tool registered today.
        """
        for _slug, tool_obj in _every_tool():
            assert isinstance(tool_obj, SquadTool), (
                f"{tool_obj!r} does not satisfy SquadTool: missing name/description/func"
            )
