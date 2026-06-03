"""
Contract tests for the Technical Author's explicit Pydantic
``args_schema`` classes - one of the per-agent test pairs (sibling
under ``tests/squad/<agent>/test_args_schemas.py``).

The TA is internal-effect (it does not fire requests at live
programmes), but ``Draft Vulnerability Report`` is the longest
authored contract on any agent and its quality gate is exactly what
keeps unfilled / under-validated drafts out of the Disclosure
Coordinator's submission path. The per-field descriptions enforced
here are what teaches the LLM the gate's grammar upstream of any
draft being written.

The generic contract loop (tool wires the explicit schema, every field
has a description, closed-world mapping) lives in
``tests/squad/_contract_assertions.py`` and is exercised below by
parametrising over ``MEMBER.schemas``. Agent-specific cases (the CVSS
vector-format description, the AuthoredDraft evidence-sanitisation
description, accept / reject shapes) stay in this file.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from squad.technical_author import (
    MEMBER,
    _DraftReportArgs,
    _FinaliseReportsArgs,
    _SanitiseEvidenceArgs,
    _TaCalculateCvssArgs,
    _TaListProgrammeReportsArgs,
    _TaLookupCweArgs,
    _TaLookupOwaspArgs,
)
from squad.tools.workspace_tools import (
    _ListRunFilesArgs,
    _ReadRunFileArgs,
)
from tests.fixtures.findings import authored_draft, draft_report_kwargs
from tests.squad._contract_assertions import (
    assert_closed_world_mapping,
    assert_field_descriptions_present,
    assert_tool_wires_explicit_schema,
)

pytestmark = pytest.mark.unit


class TestTaArgsSchemaContracts:
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

    def test_calculate_cvss_description_names_vector_format(self) -> None:
        """The CVSS vector format is documented in the field description.

        The issue body called out ``Calculate CVSS Score`` as the
        field-description sweet spot. Mirrors the equivalent test on the
        VR's copy of the schema.
        """
        desc = _TaCalculateCvssArgs.model_fields["vector"].description or ""
        assert "CVSS:3.1" in desc, (
            f"Calculate CVSS Score vector description must name the canonical"
            f" vector format (CVSS:3.1/...): got {desc!r}"
        )

    def test_draft_report_evidence_description_names_sanitisation(self) -> None:
        """The ``evidence`` field on ``AuthoredDraft`` (referenced by
        ``Draft Vulnerability Report``'s args_schema) must carry the
        upstream-sanitisation warning.

        The Disclosure Coordinator submits whatever the TA drafts to a
        public-by-default H1 report. ``Sanitise Evidence`` exists for
        this reason, and the ``evidence`` field description is the
        load-bearing place to remind the LLM to run it. Test the
        wording rather than just the presence of *any* description; a
        sibling test enforces the latter.
        """
        from models import AuthoredDraft

        desc = AuthoredDraft.model_fields["evidence"].description or ""
        lower = desc.lower()
        assert "sanitis" in lower, (
            f"AuthoredDraft.evidence description must call out Sanitise"
            f" Evidence as the upstream step: got {desc!r}"
        )


class TestSchemaAcceptReject:
    """Accept / reject contract per schema.

    Uses the conftest ``programme`` and ``disclosure_report`` fixtures
    where possible so test intent ("the selected programme",
    "a Technical-Author-shaped report") is readable at the call site.
    """

    @pytest.mark.parametrize(
        ("schema_cls", "kwargs"),
        [
            (_SanitiseEvidenceArgs, {"text": "Authorization: Bearer abc.def.ghi"}),
            (_TaLookupCweArgs, {"cwe_id": 89}),
            (_TaLookupOwaspArgs, {"query": "sql injection"}),
            (_TaCalculateCvssArgs, {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}),
            # Shared workspace acceptance cases.
            (_ListRunFilesArgs, {}),
            (_ReadRunFileArgs, {"relative_path": "verified.json"}),
        ],
    )
    def test_schema_accepts_known_input(
        self, schema_cls: type[BaseModel], kwargs: dict[str, object]
    ) -> None:
        """Known-good shapes pass model_validate without raising."""
        instance = schema_cls.model_validate(kwargs)
        assert isinstance(instance, schema_cls)

    def test_list_programme_reports_accepts_empty_payload(self) -> None:
        """``List Programme Reports`` takes no required parameters - the
        programme is sourced from the workspace at runtime."""
        instance = _TaListProgrammeReportsArgs.model_validate({})
        assert instance.page_size == 25  # default

    def test_draft_report_accepts_full_authored_shape(self) -> None:
        """``Draft Vulnerability Report`` accepts the canonical authored payload.

        The authored content is the typed ``AuthoredDraft`` (in
        ``models.report``) nested under the args_schema's ``authored``
        field; the wrapper-side plumbing (finding_index,
        verified_path) stays top-level.
        """
        instance = _DraftReportArgs.model_validate(draft_report_kwargs())
        assert instance.finding_index == 0
        assert instance.authored.cwe_id == 89
        assert instance.verified_path == "verified.json"  # default

    def test_finalise_reports_accepts_summary(self) -> None:
        """``Finalise Reports`` takes an executive summary attached to
        every consolidated report. The programme is sourced from the
        workspace at runtime."""
        instance = _FinaliseReportsArgs.model_validate(
            {
                "summary": (
                    "Tested the API surface and found one Critical SQLi at "
                    "/search. No other findings cleared the floor."
                ),
            }
        )
        assert "SQLi" in instance.summary

    @pytest.mark.parametrize(
        "schema_cls",
        [
            _SanitiseEvidenceArgs,  # text required
            _TaLookupCweArgs,  # cwe_id required
            _TaLookupOwaspArgs,  # query required
            _TaCalculateCvssArgs,  # vector required
            _DraftReportArgs,  # every authored field required
            _FinaliseReportsArgs,  # summary required
            _ReadRunFileArgs,  # relative_path required
        ],
    )
    def test_missing_required_field_rejected(self, schema_cls: type[BaseModel]) -> None:
        """At least one required field is missing: model_validate must fail."""
        with pytest.raises(ValidationError):
            schema_cls.model_validate({})

    def test_draft_report_rejects_partial_authored_payload(self) -> None:
        """Each field on ``AuthoredDraft`` is required - dropping any one
        rejects upstream of the wrapper body. Spot-check the four
        most-frequently-missed fields rather than parametrize over the
        full nine: every required field is structurally identical."""
        full_authored = authored_draft()
        for missing in ("title", "evidence", "cvss_vector", "cwe_id"):
            partial_authored = {k: v for k, v in full_authored.items() if k != missing}
            kwargs = {"finding_index": 0, "authored": partial_authored}
            with pytest.raises(ValidationError):
                _DraftReportArgs.model_validate(kwargs)

    def test_draft_report_rejects_non_numeric_cwe_id(self) -> None:
        """``AuthoredDraft.cwe_id`` is typed ``int`` - a non-numeric
        string rejects.

        Pydantic v2's lax mode coerces numeric strings ("89") to int, so
        this test only pins the case the validator actually catches: a
        non-numeric string for ``cwe_id``.
        """
        authored = {**authored_draft(), "cwe_id": "not-a-number"}
        with pytest.raises(ValidationError):
            _DraftReportArgs.model_validate({"finding_index": 0, "authored": authored})
