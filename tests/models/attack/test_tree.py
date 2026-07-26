"""tests/models/attack/test_tree.py - unit tests for models/attack/tree.py."""

from __future__ import annotations

import pytest

from models import Severity
from models.attack import AttackTree

pytestmark = pytest.mark.unit


class TestAttackTree:
    def test_accepts_vulnerability_class_probe(self, target_url):
        # The fixture covers CVE-id probes; this variant exercises the
        # vulnerability-class name shape (the second canonical probe form)
        # with a recon-evidence list to confirm the model accepts it end to end.
        item = AttackTree(
            probe="reflected XSS",
            target=f"{target_url}/?q=test",
            expected_ceiling=Severity.MEDIUM,
            rationale="parameterised endpoint reflects q into response without escaping",
            recon_evidence=[f"{target_url} hosts a Vue 2 SPA"],
        )
        assert item.probe == "reflected XSS"
        assert item.expected_ceiling == Severity.MEDIUM

    def test_recon_evidence_strips_and_filters_empties(self, target_url):
        # The recon_evidence field carries a Pydantic field_validator:
        # whitespace is trimmed off every entry, and empties are
        # dropped. Every constructor (direct call, model_validate,
        # model_validate_json on a re-loaded plan) sees the same
        # cleaned list, so the wrapper does not need its
        # own defensive shaping and the persisted artefact never carries
        # whitespace-only entries.
        item = AttackTree(
            probe="reflected XSS",
            target=f"{target_url}/?q=test",
            expected_ceiling=Severity.MEDIUM,
            rationale="parameterised endpoint reflects q into response without escaping",
            recon_evidence=["  signal one  ", "", "   ", "signal two"],
        )
        assert item.recon_evidence == ["signal one", "signal two"]
