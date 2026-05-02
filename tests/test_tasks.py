"""tests/test_tasks.py — unit tests for squad assembly and task wiring."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

pytest.importorskip("crewai")

import squad  # noqa: E402
from squad import SquadMember  # noqa: E402
from squad.disclosure_coordinator import MEMBER as DISCLOSURE_COORDINATOR  # noqa: E402
from squad.osint_analyst import MEMBER as OSINT_ANALYST  # noqa: E402
from squad.penetration_tester import MEMBER as PENETRATION_TESTER  # noqa: E402
from squad.programme_manager import MEMBER as PROGRAMME_MANAGER  # noqa: E402
from squad.technical_author import MEMBER as TECHNICAL_AUTHOR  # noqa: E402
from squad.vulnerability_researcher import MEMBER as VULNERABILITY_RESEARCHER  # noqa: E402
from tasks import build_tasks  # noqa: E402

pytestmark = pytest.mark.unit

_ALL_MEMBERS: list[SquadMember] = [
    PROGRAMME_MANAGER,
    OSINT_ANALYST,
    PENETRATION_TESTER,
    VULNERABILITY_RESEARCHER,
    TECHNICAL_AUTHOR,
    DISCLOSURE_COORDINATOR,
]


class _FakeTask:
    """Drop-in stand-in for crewai.Task that skips pydantic validation."""

    def __init__(
        self,
        description: str,
        expected_output: str,
        agent: object,
        context: list | None = None,
        human_input: bool = False,
    ) -> None:
        self.description = description
        self.expected_output = expected_output
        self.agent = agent
        self.context = context or []
        self.human_input = human_input


class TestSquadMemberRead:
    def test_all_members_load_prose(self) -> None:
        for member in _ALL_MEMBERS:
            for name in ("role", "goal", "backstory", "description", "expected_output"):
                value = member.read(name)
                assert value, f"{member.slug}/{name}.md is empty"
                assert "---" not in value, f"{member.slug}/{name}.md still contains '---'"

    def test_missing_file_raises(self, tmp_path) -> None:
        member = SquadMember(slug="missing", dir=tmp_path, tools=[])
        with pytest.raises(FileNotFoundError):
            member.read("role")


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

    def test_human_input_gates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        tasks = build_tasks(self._agents())
        select, recon, pentest, triage, write, submit = tasks
        assert select.human_input is True
        assert write.human_input is True
        for task in (recon, pentest, triage, submit):
            assert task.human_input is False
