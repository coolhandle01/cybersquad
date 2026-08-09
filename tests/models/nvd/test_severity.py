"""tests/models/nvd/test_severity.py - unit tests for the Severity enum."""

from __future__ import annotations

import pytest

from models import Severity

pytestmark = pytest.mark.unit


class TestSeverity:
    def test_all_values_present(self):
        assert {s.value for s in Severity} == {
            "informational",
            "low",
            "medium",
            "high",
            "critical",
        }

    def test_is_string_enum(self):
        assert isinstance(Severity.HIGH, str)
        assert Severity.HIGH == "high"
