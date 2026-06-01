"""tests/models/mitre/test_cwe.py - unit tests for the CWEEntry shape."""

from __future__ import annotations

import pytest

from models import CWEEntry

pytestmark = pytest.mark.unit


class TestCWEEntry:
    def test_fields_and_computed_url(self):
        entry = CWEEntry(
            cwe_id=79,
            name="Cross-site Scripting",
            description="Improper neutralisation of input during web page generation.",
        )
        assert entry.cwe_id == 79
        # url is a computed_field so it appears in model_dump for the agent.
        assert entry.url == "https://cwe.mitre.org/data/definitions/79.html"
        assert entry.model_dump()["url"].endswith("/79.html")
