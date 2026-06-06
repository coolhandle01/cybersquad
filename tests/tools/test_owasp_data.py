"""tests/tools/test_owasp_data.py - unit tests for tools/owasp_data.py."""

from __future__ import annotations

import pytest

from tools.owasp_data import OWASP_CATALOGUE, get_by_topic, lookup

pytestmark = pytest.mark.unit


class TestLookup:
    def test_exact_title_match(self):
        entries = lookup("SQL Injection Prevention")
        assert entries
        assert entries[0].topic == "SQL_Injection_Prevention"

    def test_substring_match(self):
        entries = lookup("ssrf")
        assert any("Server_Side_Request_Forgery" in e.topic for e in entries)

    def test_empty_returns_empty(self):
        assert lookup("") == []

    def test_unknown_returns_empty(self):
        assert lookup("absolutely-not-a-cheatsheet") == []


class TestGetByTopic:
    def test_returns_entry_for_known_slug(self):
        entry = get_by_topic("SQL_Injection_Prevention")
        assert entry is not None

    def test_returns_none_for_unknown(self):
        assert get_by_topic("Not_A_Real_Slug") is None


class TestCatalogueIntegrity:
    def test_topics_are_unique(self):
        topics = [e.topic for e in OWASP_CATALOGUE]
        assert len(topics) == len(set(topics))

    def test_url_format(self):
        for entry in OWASP_CATALOGUE:
            assert entry.url.startswith("https://cheatsheetseries.owasp.org/cheatsheets/")
            assert entry.url.endswith("_Cheat_Sheet.html")

    def test_every_entry_has_key_principles(self):
        for entry in OWASP_CATALOGUE:
            assert entry.key_principles
