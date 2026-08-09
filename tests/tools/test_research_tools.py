"""
tests/tools/test_research_tools.py - unit tests for tools/research_tools.py.

Coverage targets the two primitive layers the Vulnerability Researcher's
research pass depends on:

* Per-plan validation (validate_attack_forest) - the refusal branches that
  guard the LLM's output before it hits the workspace.
* Finalisation (finalise_research) - happy path writes attack_forest.json,
  refusal path raises with every error listed.
"""

from __future__ import annotations

import pytest

from models.attack import AttackForest, AttackForestFinalisationError
from tools.research_tools import (
    attack_forest_path,
    finalise_research,
    load_attack_forest,
    validate_attack_forest,
)

pytestmark = pytest.mark.unit


# Validation


class TestValidateAttackForest:
    def test_clean_plan_passes(self, attack_forest):
        report = validate_attack_forest(attack_forest)
        assert report.ok is True
        assert report.issues == []

    def test_rejects_empty_items(self, attack_forest):
        plan = attack_forest.model_copy(update={"trees": []})
        report = validate_attack_forest(plan)
        assert report.ok is False
        assert any(i.section == "trees" for i in report.issues)

    def test_rejects_item_missing_probe(self, attack_forest, attack_tree):
        plan = attack_forest.model_copy(
            update={"trees": [attack_tree.model_copy(update={"probe": "   "})]}
        )
        report = validate_attack_forest(plan)
        assert report.ok is False
        assert any(i.section == "trees[1].probe" for i in report.issues)

    def test_rejects_item_missing_target(self, attack_forest, attack_tree):
        plan = attack_forest.model_copy(
            update={"trees": [attack_tree.model_copy(update={"target": ""})]}
        )
        report = validate_attack_forest(plan)
        assert report.ok is False
        assert any(i.section == "trees[1].target" for i in report.issues)

    def test_rejects_item_missing_rationale(self, attack_forest, attack_tree):
        plan = attack_forest.model_copy(
            update={"trees": [attack_tree.model_copy(update={"rationale": ""})]}
        )
        report = validate_attack_forest(plan)
        assert report.ok is False
        assert any(i.section == "trees[1].rationale" for i in report.issues)

    def test_rejects_item_with_empty_recon_evidence(self, attack_forest, attack_tree):
        plan = attack_forest.model_copy(
            update={"trees": [attack_tree.model_copy(update={"recon_evidence": []})]}
        )
        report = validate_attack_forest(plan)
        assert report.ok is False
        assert any(i.section == "trees[1].recon_evidence" for i in report.issues)

    def test_reports_per_item_index(self, attack_forest, attack_tree):
        # Two items, second one bad - issue should reference items[2]
        good = attack_tree
        bad = attack_tree.model_copy(update={"probe": ""})
        plan = attack_forest.model_copy(update={"trees": [good, bad]})
        report = validate_attack_forest(plan)
        assert report.ok is False
        assert any(i.section == "trees[2].probe" for i in report.issues)


# Finalisation


class TestFinaliseResearch:
    def test_writes_attack_forest_json_for_clean_plan(self, attack_forest, run_dir):
        path = finalise_research(attack_forest)
        assert path == run_dir / "attack_forest.json"
        loaded = AttackForest.model_validate_json(path.read_text(encoding="utf-8"))
        assert loaded.programme_handle == attack_forest.programme_handle
        assert len(loaded.trees) == 1
        assert loaded.trees[0].probe == "CVE-2022-22965"

    def test_refuses_empty_plan(self, attack_forest, run_dir):
        plan = attack_forest.model_copy(update={"trees": []})
        with pytest.raises(AttackForestFinalisationError, match="no trees"):
            finalise_research(plan)
        assert not (run_dir / "attack_forest.json").exists()

    def test_refuses_on_validation_errors(self, attack_forest, attack_tree, run_dir):
        plan = attack_forest.model_copy(
            update={"trees": [attack_tree.model_copy(update={"recon_evidence": []})]}
        )
        with pytest.raises(AttackForestFinalisationError, match="recon_evidence"):
            finalise_research(plan)

    def test_creates_run_dir_if_missing(self, attack_forest, tmp_path, monkeypatch):
        # run_dir() may point to a directory that does not yet exist (the
        # finaliser is the first thing to write into it). The finaliser must
        # mkdir parents. The shared ``run_dir`` fixture always returns an
        # existing path, so this test stays on the explicit monkeypatch.
        nested = tmp_path / "nested" / "run"
        monkeypatch.setattr("runtime.run_dir", lambda: nested)
        path = finalise_research(attack_forest)
        assert path.exists()
        assert path.parent == nested


# Path helper


class TestAttackForestPath:
    def test_returns_attack_forest_json_under_run_dir(self, run_dir):
        assert attack_forest_path() == run_dir / "attack_forest.json"


# Loading


class TestLoadAttackForest:
    def test_round_trips_a_persisted_plan(self, attack_forest, run_dir):
        path = finalise_research(attack_forest)
        loaded = load_attack_forest(path)
        assert isinstance(loaded, AttackForest)
        assert loaded.programme_handle == attack_forest.programme_handle
        assert len(loaded.trees) == len(attack_forest.trees)
        assert loaded.trees[0].probe == attack_forest.trees[0].probe

    def test_raises_when_file_missing(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="attack plan not found"):
            load_attack_forest(tmp_path / "attack_forest.json")
