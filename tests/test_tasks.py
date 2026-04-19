"""tests/test_tasks.py — unit tests for squad assembly and task wiring."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

pytest.importorskip("crewai")

import squad  # noqa: E402
from squad import SquadMember, _parse_prompt  # noqa: E402
from squad.disclosure_coordinator import DisclosureCoordinator  # noqa: E402
from squad.osint_analyst import OsintAnalyst  # noqa: E402
from squad.penetration_tester import PenetrationTester  # noqa: E402
from squad.programme_manager import ProgrammeManager  # noqa: E402
from squad.technical_author import TechnicalAuthor  # noqa: E402
from squad.vulnerability_researcher import VulnerabilityResearcher  # noqa: E402
from tasks import build_tasks  # noqa: E402

pytestmark = pytest.mark.unit

_ALL_MEMBERS: list[type[SquadMember]] = [
    ProgrammeManager,
    OsintAnalyst,
    PenetrationTester,
    VulnerabilityResearcher,
    TechnicalAuthor,
    DisclosureCoordinator,
]


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


class TestParsePrompt:
    def test_splits_on_separator(self) -> None:
        desc, out = _parse_prompt("description\n---\noutput", "test")
        assert desc == "description"
        assert out == "output"

    def test_strips_whitespace(self) -> None:
        desc, out = _parse_prompt("  desc  \n---\n  out  ", "test")
        assert desc == "desc"
        assert out == "out"

    def test_missing_separator_raises(self) -> None:
        with pytest.raises(ValueError, match="must contain a '---' separator"):
            _parse_prompt("no separator here", "test.md")


class TestLoadPrompt:
    def test_all_members_load_successfully(self) -> None:
        for member in _ALL_MEMBERS:
            desc, out = member.load_prompt()
            assert desc, f"{member.__name__} has empty description"
            assert out, f"{member.__name__} has empty expected_output"
            assert "---" not in desc
            assert "---" not in out


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
        monkeypatch.setattr(squad, "Task", _FakeTask)
        tasks = build_tasks(self._agents())
        assert len(tasks) == 6

    def test_each_task_has_description_and_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        tasks = build_tasks(self._agents())
        for task in tasks:
            assert task.description
            assert task.expected_output

    def test_context_chaining_wired(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        tasks = build_tasks(self._agents())
        select, recon, pentest, triage, write, submit = tasks
        assert recon.context == [select]
        assert pentest.context == [recon]
        assert triage.context == [pentest, select]
        assert write.context == [triage, select]
        assert submit.context == [write]
