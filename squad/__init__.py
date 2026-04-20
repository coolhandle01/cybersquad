"""
squad/__init__.py — Abstract base for every Bounty Squad member.

Each sub-package declares its tools and slug. All prose lives in markdown:
  agent.md   — role / goal / backstory  (3 sections, '---' separated)
  prompt.md  — task description / expected output  (2 sections, '---' separated)

Assembly (LLM wiring, pipeline order, approval gates) lives in crew.py.
"""

from __future__ import annotations

import inspect
from abc import ABC
from pathlib import Path
from typing import ClassVar

from crewai import Agent, Task


def _parse_prompt(text: str, source: str) -> tuple[str, str]:
    """Split prompt.md text on the first '\\n---\\n' separator."""
    parts = text.split("\n---\n", 1)
    if len(parts) != 2:  # noqa: PLR2004
        raise ValueError(f"{source} must contain a '---' separator")
    return parts[0].strip(), parts[1].strip()


def _parse_agent_md(text: str, source: str) -> tuple[str, str, str]:
    """Split agent.md text on the first two '\\n---\\n' separators."""
    parts = text.split("\n---\n", 2)
    if len(parts) != 3:  # noqa: PLR2004
        raise ValueError(f"{source} must contain exactly 2 '---' separators")
    return parts[0].strip(), parts[1].strip(), parts[2].strip()


class SquadMember(ABC):
    """Interface every Bounty Squad member must satisfy."""

    slug: ClassVar[str]
    tools: ClassVar[list] = []

    @classmethod
    def _member_dir(cls) -> Path:
        return Path(inspect.getfile(cls)).parent

    @classmethod
    def load_agent_md(cls) -> tuple[str, str, str]:
        """Read (role, goal, backstory) from this member's agent.md."""
        path = cls._member_dir() / "agent.md"
        return _parse_agent_md(path.read_text(encoding="utf-8"), str(path))

    @classmethod
    def load_prompt(cls) -> tuple[str, str]:
        """Read (description, expected_output) from this member's prompt.md."""
        path = cls._member_dir() / "prompt.md"
        return _parse_prompt(path.read_text(encoding="utf-8"), str(path))

    @classmethod
    def build_agent(cls, llm: object, verbose: bool = False) -> Agent:
        """Construct a CrewAI Agent from agent.md and cls.tools."""
        role, goal, backstory = cls.load_agent_md()
        return Agent(
            role=role,
            goal=goal,
            backstory=backstory,
            tools=cls.tools,
            allow_delegation=False,
            llm=llm,
            verbose=verbose,
        )

    @classmethod
    def build_task(
        cls,
        agent: Agent,
        context: list[Task] | None = None,
        human_input: bool = False,
    ) -> Task:
        """Create a Task wired to the given agent and optional upstream context."""
        description, expected_output = cls.load_prompt()
        return Task(
            description=description,
            expected_output=expected_output,
            agent=agent,
            context=context or [],
            human_input=human_input,
        )
