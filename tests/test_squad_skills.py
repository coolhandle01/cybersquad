"""
tests/test_squad_skills.py - filesystem-level checks on the runtime skill
catalogue (issue #62).

The crewai.skills loader is responsible for parsing SKILL.md frontmatter and
attaching skills to agents. These tests assert the contract from the cybersquad
side: the expected skill directories exist, each one has a SKILL.md, and the
frontmatter name matches the directory name (the loader uses the name field as
the skill identifier downstream).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

import pytest

from squad import SQUAD_SKILLS_DIR
from squad.osint_analyst import MEMBER as OSINT_ANALYST
from squad.programme_manager import MEMBER as PROGRAMME_MANAGER

pytestmark = pytest.mark.unit

# Per crewai.skills.SkillFrontmatter: lowercase alphanumeric + hyphens, 1-64.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def _frontmatter_name(skill_md: Path) -> str:
    """Pull the `name:` value out of a SKILL.md frontmatter block."""
    text = skill_md.read_text(encoding="utf-8")
    head, _, _ = text.partition("\n---\n")
    head = head.removeprefix("---\n")
    for line in head.splitlines():
        if line.startswith("name:"):
            return line.split(":", 1)[1].strip()
    raise AssertionError(f"{skill_md} has no `name:` in frontmatter")


class TestSquadWideSkills:
    def test_skills_dir_exists(self) -> None:
        assert SQUAD_SKILLS_DIR.is_dir(), SQUAD_SKILLS_DIR

    def test_scope_discipline_skill_present(self) -> None:
        skill_md = SQUAD_SKILLS_DIR / "scope-discipline" / "SKILL.md"
        assert skill_md.is_file()
        assert _frontmatter_name(skill_md) == "scope-discipline"


class TestProgrammeManagerSkills:
    EXPECTED: ClassVar[set[str]] = {
        "programme-selection-scoring",
        "policy-reading-discipline",
        "access-authorisation",
    }

    def test_skills_dir_exists(self) -> None:
        assert PROGRAMME_MANAGER.skills_dir.is_dir()

    def test_expected_skills_present(self) -> None:
        found = {
            child.name
            for child in PROGRAMME_MANAGER.skills_dir.iterdir()
            if child.is_dir() and (child / "SKILL.md").is_file()
        }
        assert self.EXPECTED.issubset(found), found

    @pytest.mark.parametrize("slug", sorted(EXPECTED))
    def test_skill_frontmatter_name_matches_dir(self, slug: str) -> None:
        skill_md = PROGRAMME_MANAGER.skills_dir / slug / "SKILL.md"
        name = _frontmatter_name(skill_md)
        assert name == slug, (name, slug)
        assert NAME_RE.match(name), name


class TestOsintAnalystSkills:
    EXPECTED: ClassVar[set[str]] = {
        "recon-flow",
    }

    def test_skills_dir_exists(self) -> None:
        assert OSINT_ANALYST.skills_dir.is_dir()

    def test_expected_skills_present(self) -> None:
        found = {
            child.name
            for child in OSINT_ANALYST.skills_dir.iterdir()
            if child.is_dir() and (child / "SKILL.md").is_file()
        }
        assert self.EXPECTED.issubset(found), found

    @pytest.mark.parametrize("slug", sorted(EXPECTED))
    def test_skill_frontmatter_name_matches_dir(self, slug: str) -> None:
        skill_md = OSINT_ANALYST.skills_dir / slug / "SKILL.md"
        name = _frontmatter_name(skill_md)
        assert name == slug, (name, slug)
        assert NAME_RE.match(name), name
