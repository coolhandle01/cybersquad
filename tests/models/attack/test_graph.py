"""tests/models/attack/test_graph.py - unit tests for models/attack/graph.py."""

from __future__ import annotations

import pytest

from models.attack import AttackGraph

pytestmark = pytest.mark.unit


class TestAttackGraph:
    def test_valid_recon_result(self, recon_result):
        assert len(recon_result.subdomains) == 2
        assert len(recon_result.endpoints) == 1

    def test_completed_at_is_set(self, recon_result):
        assert recon_result.completed_at is not None

    def test_serialise_roundtrip(self, recon_result):
        json_str = recon_result.model_dump_json()
        restored = AttackGraph.model_validate_json(json_str)
        assert restored.programme.handle == recon_result.programme.handle
        assert len(restored.endpoints) == len(recon_result.endpoints)
