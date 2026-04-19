"""tests/test_tasks.py — unit tests for tasks.py prompt loader and task builder."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

pytest.importorskip("crewai")

from tasks import _PROMPTS_DIR, _load, build_tasks  # noqa: E402

pytestmark = pytest.mark.unit


class _FakeTask:
    """Drop-in stand-in for crewai.Task that skips pydantic validation."""

    def __init__(
        self,
        description: str,
        expected_output: str,
        agent: object,
        context: list | None = None,
    ) -> None:
        self.description = description
        self.expected_output = expected_output
        self.agent = agent
        self.context = context or []


class TestLoad:
    def test_returns_description_and_output(self) -> None:
        desc, out = _load("programme-manager.md")
        assert desc
        assert out
        assert "---" not in desc
        assert "---" not in out

    def test_all_prompt_files_load(self) -> None:
        for path in Path(_PROMPTS_DIR).glob("*.md"):
            desc, out = _load(path.name)
            assert desc, f"{path.name} has empty description"
            assert out, f"{path.name} has empty expected_output"

    def test_missing_separator_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bad = tmp_path / "bad.md"
        bad.write_text("just a description, no separator")
        monkeypatch.setattr("tasks._PROMPTS_DIR", tmp_path)
        with pytest.raises(ValueError, match="must contain a '---' separator"):
            _load("bad.md")


class TestBuildTasks:
    def _agents(self) -> dict:
        roles = [
            "programme_manager",
            "osint_analyst",
            "penetration_tester",
            "vulnerability_researcher",
            "technical_author",
            "disclosure_coordinator",
        ]
        return {role: MagicMock(name=role) for role in roles}

    def test_returns_six_tasks_in_order(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("tasks.Task", _FakeTask)
        tasks = build_tasks(self._agents())
        assert len(tasks) == 6

    def test_each_task_has_description_and_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("tasks.Task", _FakeTask)
        tasks = build_tasks(self._agents())
        for task in tasks:
            assert task.description
            assert task.expected_output

    def test_context_chaining_wired(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("tasks.Task", _FakeTask)
        tasks = build_tasks(self._agents())
        select, recon, pentest, triage, write, submit = tasks
        assert recon.context == [select]
        assert pentest.context == [recon]
        assert triage.context == [pentest, select]
        assert write.context == [triage, select]
        assert submit.context == [write]
