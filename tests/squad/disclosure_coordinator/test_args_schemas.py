"""
Contract tests for the Disclosure Coordinator's explicit Pydantic
``args_schema`` classes - one of the per-agent test pairs (sibling
under ``tests/squad/<agent>/test_args_schemas.py``).

The DC is the only agent whose tools have an irreversible public
side-effect - ``Submit Report`` files a report on hackerone.com that the
programme's triage team sees and the operator cannot silently retract.
The per-field description for ``report`` names the consequence; the
contract test ensures the description is present and that the
irreversibility wording survives any future rewording.

The generic contract loop (tool wires the explicit schema, every field
has a description, closed-world mapping) lives in
``tests/squad/_contract_assertions.py`` and is exercised below by
parametrising over ``MEMBER.schemas`` - the per-agent schema registry
moved onto the squad member alongside ``tools``. Agent-specific cases
(``Submit Report``'s irreversibility wording, accept / reject shapes)
stay in this file.

The wrappers do not call the H1 API at validation time - the existing
H1 behavioural tests in ``test_tools.py`` keep their mocking; this
file only exercises the schema contract.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from squad.disclosure_coordinator import (
    MEMBER,
    _CheckDuplicateArgs,
    _SubmitReportArgs,
)
from tests.squad._contract_assertions import (
    assert_closed_world_mapping,
    assert_field_descriptions_present,
    assert_tool_wires_explicit_schema,
)

pytestmark = pytest.mark.unit


class TestDcArgsSchemaContracts:
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

    def test_submit_report_description_names_irreversibility(self) -> None:
        """The irreversible operation's field description must name the
        consequence of a mis-call.

        The agent reading ``Submit Report``'s schema needs to know that a
        wrong ``programme_handle`` inside the payload publishes a report
        to the wrong target - the schema description is the load-bearing
        place to say that out loud. Test the wording rather than just
        the presence of *any* description; a sibling test (
        ``test_every_field_has_description`` above) already enforces the
        latter.
        """
        desc = _SubmitReportArgs.model_fields["report"].description or ""
        # "Irreversible" is the framing the issue body uses; we look for
        # the broader semantic signal (irreversible + programme_handle
        # warning) rather than a single literal so the description can be
        # reworded without breaking the test.
        lower = desc.lower()
        assert "irreversible" in lower or "cannot" in lower, (
            f"Submit Report description must name the irreversible nature: got {desc!r}"
        )
        assert "programme_handle" in lower or "programme handle" in lower, (
            "Submit Report description must call out the programme_handle "
            f"mis-call risk: got {desc!r}"
        )


class TestSchemaAcceptReject:
    """Accept / reject contract per schema.

    URL / hostname-taking schemas don't apply here - the DC's tools take
    a serialised report payload or a programme handle, both of which are
    well served by the ``disclosure_report`` and ``programme`` fixtures.
    """

    def test_submit_report_accepts_dict_payload(self, disclosure_report) -> None:
        """CrewAI hands the args_schema a dict shaped like DisclosureReport.

        Uses the ``disclosure_report`` conftest fixture so test intent
        ("a real, in-scope report") is readable at the call site rather
        than a hand-rolled dict literal.
        """
        instance = _SubmitReportArgs.model_validate({"report": disclosure_report.model_dump()})
        assert instance.report.programme_handle == disclosure_report.programme_handle
        assert instance.report.title == disclosure_report.title

    def test_submit_report_accepts_typed_model(self, disclosure_report) -> None:
        """Direct test invocations pass a DisclosureReport instance; the
        schema must accept that too (the both-shapes adapter pattern)."""
        instance = _SubmitReportArgs.model_validate({"report": disclosure_report})
        assert instance.report.programme_handle == disclosure_report.programme_handle

    def test_submit_report_rejects_mis_shaped_report(self) -> None:
        """A dict that doesn't validate as DisclosureReport rejects
        upstream of the wrapper - the whole point of the typed
        parameter is the schema reject."""
        with pytest.raises(ValidationError):
            _SubmitReportArgs.model_validate({"report": {"not_a_real_field": "x"}})

    def test_check_duplicate_accepts_title(self, disclosure_report) -> None:
        """Check Duplicate takes the draft title - the programme is
        sourced from the workspace at runtime."""
        instance = _CheckDuplicateArgs.model_validate({"title": disclosure_report.title})
        assert instance.title == disclosure_report.title

    @pytest.mark.parametrize(
        "schema_cls",
        [
            _SubmitReportArgs,
            _CheckDuplicateArgs,
        ],
    )
    def test_missing_required_fields_rejected(self, schema_cls: type[BaseModel]) -> None:
        """Every DC typed-tool schema rejects an empty payload - all fields are required."""
        with pytest.raises(ValidationError):
            schema_cls.model_validate({})
