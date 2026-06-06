"""tests/models/mitre/test_cwe.py - unit tests for the CWE type."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import CWE

pytestmark = pytest.mark.unit


class TestCWE:
    def test_from_bare_int_enriches_from_corpus(self):
        cwe = CWE.model_validate(79)
        assert cwe.cwe_id == 79
        # name + description come from MITRE's corpus, not the input.
        assert "Cross-site" in cwe.name
        assert cwe.description.strip()
        # url is a computed_field so it appears in model_dump for the agent.
        assert cwe.url == "https://cwe.mitre.org/data/definitions/79.html"
        assert cwe.model_dump()["url"].endswith("/79.html")

    def test_input_name_description_are_ignored_in_favour_of_corpus(self):
        # A mapping carrying bogus prose still resolves to MITRE's wording -
        # a CWE is whatever the corpus says it is.
        cwe = CWE.model_validate({"cwe_id": 89, "name": "wrong", "description": "wrong"})
        assert cwe.cwe_id == 89
        assert cwe.name != "wrong"
        assert "SQL" in cwe.name

    def test_resolves_any_valid_cwe_not_just_a_curated_subset(self):
        cwe = CWE.model_validate(120)  # Classic Buffer Overflow
        assert cwe.cwe_id == 120
        assert cwe.name.strip()

    def test_rejects_non_cwe_id(self):
        with pytest.raises(ValidationError):
            CWE.model_validate(999999)

    def test_rejects_bool(self):
        with pytest.raises(ValidationError):
            CWE.model_validate(True)

    def test_get_returns_none_on_miss(self):
        assert CWE.get(999999) is None
        assert CWE.get(89) is not None
