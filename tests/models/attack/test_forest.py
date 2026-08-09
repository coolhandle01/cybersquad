"""tests/models/attack/test_forest.py - unit tests for models/attack/forest.py."""

from __future__ import annotations

import pytest

from models import Severity
from models.attack import AttackForest

pytestmark = pytest.mark.unit


class TestAttackForest:
    def test_serialise_roundtrip(self, attack_forest):
        restored = AttackForest.model_validate_json(attack_forest.model_dump_json())
        assert restored.programme_handle == attack_forest.programme_handle
        assert restored.trees[0].expected_ceiling == Severity.CRITICAL
