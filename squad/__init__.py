"""
squad/__init__.py — Abstract base for every Bounty Squad member.

Each sub-package defines its @tool functions, a SquadMember subclass
with build_agent(), and a prompt.md. Assembly (LLM wiring, dict keys,
pipeline order) lives in agents.py and tasks.py.
"""

from __future__ import annotations

import inspect
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar

from crewai import Agent, Task


def _parse_prompt(text: str, source: str) -> tuple[str, str]:
    """Split prompt text on the first '\\n---\\n' separator."""
    parts = text.split("\n---\n", 1)
    if len(parts) != 2:  # noqa: PLR2004
        raise ValueError(f"{source} must contain a '---' separator")
    return parts[0].strip(), parts[1].strip()


class SquadMember(ABC):
    """Interface every Bounty Squad member must satisfy."""

    slug: ClassVar[str]

    @classmethod
    @abstractmethod
    def build_agent(cls, llm: object, verbose: bool = False) -> Agent:
        """Return a configured CrewAI Agent for this role."""
        ...

    @classmethod
    def load_prompt(cls) -> tuple[str, str]:
        """Read (description, expected_output) from this member's prompt.md."""
        path = Path(inspect.getfile(cls)).parent / "prompt.md"
        return _parse_prompt(path.read_text(encoding="utf-8"), str(path))

    @classmethod
    def build_task(cls, agent: Agent, context: list[Task] | None = None) -> Task:
        """Create a Task wired to the given agent and optional upstream context."""
        description, expected_output = cls.load_prompt()
        return Task(
            description=description,
            expected_output=expected_output,
            agent=agent,
            context=context or [],
        )
