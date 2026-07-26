"""tests/test_tasks.py - unit tests for squad assembly and task wiring."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

pytest.importorskip("crewai")

import squad
from squad import SquadMember
from squad.disclosure_coordinator import MEMBER as DISCLOSURE_COORDINATOR
from squad.osint_analyst import MEMBER as OSINT_ANALYST
from squad.penetration_tester import MEMBER as PENETRATION_TESTER
from squad.programme_manager import MEMBER as PROGRAMME_MANAGER
from squad.technical_author import MEMBER as TECHNICAL_AUTHOR
from squad.vulnerability_researcher import MEMBER as VULNERABILITY_RESEARCHER
from tasks import build_tasks

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
        name: str = "",
        context: list | None = None,
        human_input: bool = False,
        guardrail: object = None,
        guardrail_max_retries: int | None = None,
    ) -> None:
        self.name = name
        self.description = description
        self.expected_output = expected_output
        self.agent = agent
        self.context = context or []
        self.human_input = human_input
        self.guardrail = guardrail
        self.guardrail_max_retries = guardrail_max_retries


class TestSquadMemberRead:
    def test_all_members_load_prose(self) -> None:
        for member in _ALL_MEMBERS:
            for name in ("role", "goal", "backstory"):
                value = member.read(name)
                assert value, f"{member.slug}/{name}.md is empty"
                assert "---" not in value, f"{member.slug}/{name}.md still contains '---'"

    def test_missing_file_raises(self, tmp_path) -> None:
        member = SquadMember(dir=tmp_path, tools=[])
        with pytest.raises(FileNotFoundError):
            member.read("role")


class TestAttackForestWiring:
    """The typed attack plan is the contract between VR research, PT, and VR
    triage. Both consumers must expose Read Attack Plan."""

    def test_penetration_tester_has_read_attack_forest_tool(self) -> None:
        from squad import read_attack_forest_tool

        assert read_attack_forest_tool in PENETRATION_TESTER.tools

    def test_vulnerability_researcher_has_read_attack_forest_tool(self) -> None:
        from squad import read_attack_forest_tool

        assert read_attack_forest_tool in VULNERABILITY_RESEARCHER.tools


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

    def test_returns_seven_tasks_in_order(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        tasks = build_tasks(self._agents())
        assert len(tasks) == 7

    def test_each_task_has_description_and_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        tasks = build_tasks(self._agents())
        for task in tasks:
            assert task.description
            assert task.expected_output

    def test_each_task_has_display_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Every task carries a human-readable ``name`` from its ``name.md``,
        so a task self-describes when something walks ``crew.tasks``."""
        monkeypatch.setattr(squad, "Task", _FakeTask)
        tasks = build_tasks(self._agents())
        for task in tasks:
            assert task.name, "task is missing a display name"
            assert "---" not in task.name

    def test_vr_two_tasks_have_distinct_names(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The VR owns both research and triage; per-task ``name.md`` keeps them
        distinct rather than collapsing to the shared agent role."""
        monkeypatch.setattr(squad, "Task", _FakeTask)
        _select, _recon, research, _pentest, triage, _write, _submit = build_tasks(self._agents())
        assert research.name != triage.name
        assert research.agent is triage.agent  # same agent, different tasks

    def test_context_chaining_wired(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        tasks = build_tasks(self._agents())
        select, recon, research, pentest, triage, write, submit = tasks
        assert recon.context == [select]
        assert research.context == [recon, select]
        assert pentest.context == [research, recon, select]
        assert triage.context == [pentest, research, select]
        assert write.context == [triage, select]
        assert submit.context == [write]

    def test_select_task_wired_with_guardrail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from squad.guardrails import validate_select_output

        monkeypatch.setattr(squad, "Task", _FakeTask)
        select, *_rest = build_tasks(self._agents())
        assert select.guardrail is validate_select_output
        assert select.guardrail_max_retries == 2

    def test_only_select_task_is_guarded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(squad, "Task", _FakeTask)
        select, *rest = build_tasks(self._agents())
        assert select.guardrail is not None
        assert all(t.guardrail is None for t in rest)

    def test_human_input_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import importlib

        import config as config_mod
        import tasks as tasks_mod

        monkeypatch.setenv("CYBERSQUAD_HUMAN_INPUT", "true")
        importlib.reload(config_mod)
        importlib.reload(tasks_mod)
        monkeypatch.setattr(squad, "Task", _FakeTask)

        from tasks import build_tasks as _build_tasks

        tasks = _build_tasks(self._agents())
        assert all(t.human_input is True for t in tasks)

    def test_human_input_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import importlib

        import config as config_mod
        import tasks as tasks_mod

        monkeypatch.setenv("CYBERSQUAD_HUMAN_INPUT", "false")
        importlib.reload(config_mod)
        importlib.reload(tasks_mod)
        monkeypatch.setattr(squad, "Task", _FakeTask)

        from tasks import build_tasks as _build_tasks

        tasks = _build_tasks(self._agents())
        assert all(t.human_input is False for t in tasks)
