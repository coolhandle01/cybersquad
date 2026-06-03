"""Unit tests for squad.guardrails.validate_select_output.

The guardrail validates the *workspace artefact* (``<run_dir>/programme.json``,
the snapshot recon reads via ``current_programme()``), not the agent's raw
answer - so these tests stage the rundir state (via the shared ``run_dir`` /
``programme_in_workspace`` fixtures) and drive the guardrail with a real
``TaskOutput`` from ``make_task_output``.
"""

from __future__ import annotations

import pytest

from squad.guardrails import validate_select_output

pytestmark = pytest.mark.unit


def test_passes_with_valid_programme_in_workspace(programme_in_workspace, make_task_output):
    """A persisted, schema-valid programme.json passes and returns the raw through."""
    result = make_task_output("Selected test-programme; see programme.json.")
    ok, value = validate_select_output(result)
    assert ok is True
    assert value == "Selected test-programme; see programme.json."


def test_rejects_missing_programme_json(run_dir, make_task_output):
    """Rundir bound but no programme.json written -> reject, point at the save tool."""
    ok, msg = validate_select_output(make_task_output("done"))
    assert ok is False
    assert "Save Selected Programme" in msg


def test_rejects_when_run_dir_unbound(monkeypatch, make_task_output):
    """No programme bound at all (run_dir() raises RuntimeError) -> reject."""
    monkeypatch.setattr("runtime.programme_handle", "")
    monkeypatch.setattr("runtime.run_id", "")
    ok, msg = validate_select_output(make_task_output("done"))
    assert ok is False
    assert "Save Selected Programme" in msg


def test_rejects_malformed_programme_json(run_dir, make_task_output):
    """A programme.json that fails schema validation -> reject with the reason."""
    (run_dir / "programme.json").write_text('{"handle": "x"}', encoding="utf-8")
    ok, msg = validate_select_output(make_task_output("done"))
    assert ok is False
    assert "schema validation" in msg


def test_rejects_empty_handle(programme, run_dir, make_task_output):
    """A well-formed programme.json with an empty handle -> reject."""
    blank = programme.model_copy(update={"handle": ""})
    (run_dir / "programme.json").write_text(blank.model_dump_json(), encoding="utf-8")
    ok, msg = validate_select_output(make_task_output("done"))
    assert ok is False
    assert "handle" in msg


@pytest.mark.parametrize("raw", ["", "free-text briefing", '{"handle": "test-programme"}'])
def test_passes_raw_unchanged(programme_in_workspace, make_task_output, raw):
    """On success the second tuple element is the task's raw output, verbatim."""
    ok, value = validate_select_output(make_task_output(raw))
    assert ok is True
    assert value == raw
