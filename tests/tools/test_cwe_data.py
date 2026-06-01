"""tests/tools/test_cwe_data.py - unit tests for tools/cwe_data.py.

cwe_data is a thin wrapper over the bundled MITRE corpus (cwe2): given a CWE id,
return its MITRE name + description. No local catalogue or keyword index - only
id-based enrichment.
"""

from __future__ import annotations

import pytest

from tools.cwe_data import get_by_id

pytestmark = pytest.mark.unit


class TestGetById:
    def test_returns_entry_for_known(self):
        entry = get_by_id(79)
        assert entry is not None
        # Name + description come straight from MITRE's corpus.
        assert "Cross-site" in entry.name
        assert entry.description.strip()
        assert entry.url == "https://cwe.mitre.org/data/definitions/79.html"

    def test_resolves_any_valid_cwe_not_just_a_curated_subset(self):
        # A CWE that was never in the old hand-vendored 29-entry catalogue still
        # resolves - the corpus is the source, not a local list.
        entry = get_by_id(120)  # Classic Buffer Overflow
        assert entry is not None
        assert entry.cwe_id == 120
        assert entry.name.strip()

    def test_returns_none_for_unknown(self):
        assert get_by_id(999999) is None
