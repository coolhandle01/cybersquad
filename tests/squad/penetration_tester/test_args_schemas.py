"""
tests/squad/penetration_tester/test_args_schemas.py - the generic contract loop
for the explicit Pydantic ``args_schema`` every Penetration Tester wrapper carries.

The PT agent's tools hit live programmes; a mis-call costs money and
noise. The ``args_schema`` is the per-tool contract the LLM is shown
when picking the tool.

This file holds the generic contract loop - tool wires the explicit
schema, every field has a description, closed-world mapping - exercised
by parametrising over ``MEMBER.schemas`` (the per-agent schema registry
that moved onto the squad member alongside ``tools``) and calling the
shared assertions in ``tests/squad/_contract_assertions.py``. The
agent-specific accept / reject cases (StrEnum payload reject tables,
JWT-specific shapes, recon-path required-field rejection) live in
``test_args_schema_cases.py``.

The behavioural tests (``test_ssrf.py``, ``test_idor.py`` etc.) cover
probe behaviour separately.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from squad.penetration_tester import MEMBER
from tests.squad._contract_assertions import (
    assert_closed_world_mapping,
    assert_field_descriptions_present,
    assert_tool_wires_explicit_schema,
)

pytestmark = pytest.mark.unit


class TestPtArgsSchemaContracts:
    @pytest.mark.parametrize("tool_name", sorted(MEMBER.schemas))
    def test_tool_wires_explicit_schema(self, tool_name: str) -> None:
        assert_tool_wires_explicit_schema(MEMBER, tool_name)

    @pytest.mark.parametrize(
        ("tool_name", "schema_cls"),
        sorted(MEMBER.schemas.items()),
        ids=sorted(MEMBER.schemas),
    )
    def test_every_field_has_description(self, tool_name: str, schema_cls: type[BaseModel]) -> None:
        assert_field_descriptions_present(tool_name, schema_cls)

    def test_closed_world_mapping(self) -> None:
        assert_closed_world_mapping(MEMBER)
