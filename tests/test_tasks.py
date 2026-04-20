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
        human_input: bool = False,
    ) -> None:
        self.description = description
        self.expected_output = expected_output
        self.agent = agent
        self.context = context or []
        self.human_input = human_input


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
        return {
            role: MagicMock(name=role)
            for role in [
                "programme_manager",
                "osint_analyst",
                "penetration_tester",
                "vulnerability_researcher",
                "technical_author",
                "disclosure_coordinator",
            ]
        }

    def _pm_agents(self) -> dict:
        return {"programme_manager": MagicMock(name="programme_manager")}

    # standup phase
    def test_standup_returns_five_tasks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        tasks = build_tasks(self._agents(), phase="standup")
        assert len(tasks) == 5

    def test_standup_context_chaining(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        recon, pentest, triage, write, submit = build_tasks(self._agents(), phase="standup")
        assert pentest.context == [recon]
        assert triage.context == [recon, pentest]
        assert write.context == [triage]
        assert submit.context == [write]

    def test_standup_human_input_on_write_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        recon, pentest, triage, write, submit = build_tasks(self._agents(), phase="standup")
        assert write.human_input is True
        for task in (recon, pentest, triage, submit):
            assert task.human_input is False

    # PM-only phases
    def test_select_programme_returns_one_task_with_human_input(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        tasks = build_tasks(self._pm_agents(), phase="select_programme")
        assert len(tasks) == 1
        assert tasks[0].human_input is True

    def test_campaign_kickoff_returns_one_task_with_human_input(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        tasks = build_tasks(self._pm_agents(), phase="campaign_kickoff")
        assert len(tasks) == 1
        assert tasks[0].human_input is True

    def test_campaign_review_returns_one_task_with_human_input(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        tasks = build_tasks(self._pm_agents(), phase="campaign_review")
        assert len(tasks) == 1
        assert tasks[0].human_input is True

    def test_campaign_retro_returns_one_task_no_human_input(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        tasks = build_tasks(self._pm_agents(), phase="campaign_retro")
        assert len(tasks) == 1
        assert tasks[0].human_input is False

    def test_unknown_phase_defaults_to_standup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        tasks = build_tasks(self._agents(), phase="unknown_phase")
        assert len(tasks) == 5

    def test_each_task_has_description_and_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        phases = (
            "standup",
            "select_programme",
            "campaign_kickoff",
            "campaign_review",
            "campaign_retro",
        )
        for phase in phases:
            agents = self._agents() if phase == "standup" else self._pm_agents()
            tasks = build_tasks(agents, phase=phase)
            for task in tasks:
                assert task.description, f"{phase} task has empty description"
                assert task.expected_output, f"{phase} task has empty expected_output"


class TestPhasePrompts:
    """Verify the PM phase prompt files load and parse correctly."""

    def test_kickoff_prompt_loads(self) -> None:
        desc, out = _parse_prompt(
            (ProgrammeManager._member_dir() / "kickoff.md").read_text(encoding="utf-8"),
            "kickoff.md",
        )
        assert desc
        assert out

    def test_review_prompt_loads(self) -> None:
        desc, out = _parse_prompt(
            (ProgrammeManager._member_dir() / "review.md").read_text(encoding="utf-8"),
            "review.md",
        )
        assert desc
        assert out

    def test_retro_prompt_loads(self) -> None:
        desc, out = _parse_prompt(
            (ProgrammeManager._member_dir() / "retro.md").read_text(encoding="utf-8"),
            "retro.md",
        )
        assert desc
        assert out
