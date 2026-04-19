"""Technical Author — writes professional H1-format disclosure reports."""

from __future__ import annotations

from squad import SquadMember


class TechnicalAuthor(SquadMember):
    slug = "technical_author"
    # inherits tools = [] from SquadMember — works from context alone
