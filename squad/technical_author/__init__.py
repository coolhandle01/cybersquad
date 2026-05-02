"""Technical Author — writes professional H1-format disclosure reports."""

from __future__ import annotations

from pathlib import Path

from squad import SquadMember

MEMBER = SquadMember(
    slug="technical_author",
    dir=Path(__file__).parent,
)
