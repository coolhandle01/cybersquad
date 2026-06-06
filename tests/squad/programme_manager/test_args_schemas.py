"""
Contract tests for the Programme Manager's explicit Pydantic
``args_schema`` classes - one of the per-agent test pairs (sibling
under ``tests/squad/<agent>/test_args_schemas.py``).

The PM's tools are the highest-stakes targeting surface in the squad: a
mis-call picks the wrong programme, and downstream every probe runs
against the wrong target. The ``handle`` field in particular is the
most-mis-called field type in the codebase, so the per-field
descriptions enforced here are the primary signal the LLM reads.

The generic contract loop (tool wires the explicit schema, every field
has a description, closed-world mapping) lives in
``tests/squad/_contract_assertions.py`` and is exercised below by
parametrising over ``MEMBER.schemas`` - the per-agent schema registry
moved onto the squad member alongside ``tools``. Agent-specific
accept / reject cases stay in this file.

The wrappers do not call the H1 API at validation time - the existing
H1 behavioural tests in ``test_tools.py`` keep their mocking; this
file only exercises the schema contract.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from models.h1 import ScopeType, SubmissionState
from squad.programme_manager import (
    MEMBER,
    _BrowseProgrammesArgs,
    _HydrateProgrammeArgs,
    _SaveProgrammeArgs,
)
from tests.squad._contract_assertions import (
    assert_closed_world_mapping,
    assert_field_descriptions_present,
    assert_tool_wires_explicit_schema,
)

pytestmark = pytest.mark.unit


class TestPmArgsSchemaContracts:
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


class TestSchemaAcceptReject:
    """Accept / reject contract per schema.

    The parametrize below carries cases that do not need a fixture-derived
    programme handle. Hydrate / Save take a ``handle`` and use the
    ``programme`` fixture via dedicated test methods so test intent
    ("the selected programme") is readable at the call site.
    """

    @pytest.mark.parametrize(
        ("schema_cls", "kwargs"),
        [
            # Browse: every field defaults to None, so the empty kwargs case
            # is the canonical "let H1 apply defaults" call.
            (_BrowseProgrammesArgs, {}),
            (
                _BrowseProgrammesArgs,
                {
                    # StrEnum values are lowercase Python-side; the
                    # wrapper uppercases asset_type before sending it to
                    # H1.
                    "asset_type": "wildcard",
                    "bookmarked": True,
                    "offers_bounties": True,
                    "submission_state": "open",
                    "sort": "-launched_at",
                    "limit": 50,
                },
            ),
        ],
    )
    def test_schema_accepts_known_input(
        self, schema_cls: type[BaseModel], kwargs: dict[str, object]
    ) -> None:
        """Known-good shapes pass model_validate without raising."""
        instance = schema_cls.model_validate(kwargs)
        assert isinstance(instance, schema_cls)

    def test_browse_rejects_unknown_asset_type(self) -> None:
        """``asset_type`` is a StrEnum; H1's documented types are the only
        acceptable values."""
        with pytest.raises(ValidationError):
            _BrowseProgrammesArgs.model_validate({"asset_type": "not-a-real-type"})

    def test_browse_rejects_unknown_submission_state(self) -> None:
        """``submission_state`` is a StrEnum scoped to the documented H1
        filter values (open / disabled / paused)."""
        with pytest.raises(ValidationError):
            _BrowseProgrammesArgs.model_validate({"submission_state": "closed"})

    def test_browse_accepts_strenum_members_directly(self) -> None:
        """Passing the StrEnum members (rather than their string values)
        also validates - the wrapper is happy with either."""
        instance = _BrowseProgrammesArgs.model_validate(
            {
                "asset_type": ScopeType.WILDCARD,
                "submission_state": SubmissionState.OPEN,
            }
        )
        assert instance.asset_type is ScopeType.WILDCARD
        assert instance.submission_state is SubmissionState.OPEN

    def test_hydrate_accepts_programme_handle(self, programme) -> None:
        """Hydrate takes the exact handle of the selected programme."""
        instance = _HydrateProgrammeArgs.model_validate({"handle": programme.handle})
        assert instance.handle == programme.handle

    def test_save_accepts_programme_handle(self, programme) -> None:
        """Save takes the exact handle of the selected programme."""
        instance = _SaveProgrammeArgs.model_validate({"handle": programme.handle})
        assert instance.handle == programme.handle

    @pytest.mark.parametrize(
        "schema_cls",
        [
            _HydrateProgrammeArgs,
            _SaveProgrammeArgs,
        ],
    )
    def test_missing_required_handle_rejected(self, schema_cls: type[BaseModel]) -> None:
        """``handle`` is required on every handle-taking PM typed-tool schema."""
        with pytest.raises(ValidationError):
            schema_cls.model_validate({})

    def test_browse_ignores_unknown_fields(self) -> None:
        """Browse's filter fields are all optional - extras silently drop.

        Pydantic's default is ``extra='ignore'`` and we keep that here:
        H1's wire layer ignores unknown ``filter[*]`` keys silently
        anyway, so additional strictness would only confuse agents that
        pass through an extra key the wrapper would happily forward.
        """
        instance = _BrowseProgrammesArgs.model_validate(
            {"offers_bounties": True, "nope": "ignored"}
        )
        assert instance.offers_bounties is True
        assert not hasattr(instance, "nope")

    def test_browse_rejects_non_numeric_limit(self) -> None:
        """``limit`` is typed ``int | None`` - a non-numeric string rejects.

        Pydantic v2's lax mode coerces numeric strings ("50") to int and
        accepts boolish strings ("yes") for bool fields, so this test
        only pins the case the validator actually catches: a non-numeric
        string for ``limit``.
        """
        with pytest.raises(ValidationError):
            _BrowseProgrammesArgs.model_validate({"limit": "not-a-number"})
