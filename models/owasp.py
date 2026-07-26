"""
models/owasp.py - typed shape for an OWASP Cheat Sheet entry.

Lives in models/ alongside the per-domain shapes (cve / cwe / h1 / etc.).
The Cheat Sheet catalogue data and the substring-match lookup live in
``tools/owasp_data.py``; this module is just the row contract consumers
import to type-check return shapes against.
"""

from __future__ import annotations

from pydantic import BaseModel, computed_field

_BASE_URL = "https://cheatsheetseries.owasp.org/cheatsheets"


class OWASPEntry(BaseModel):
    """A single OWASP Cheat Sheet entry."""

    topic: str  # canonical slug, used to build URL
    title: str
    key_principles: list[str]
    aliases: list[str] = []  # short keywords the TA may use to find this sheet

    # Exposed as a computed_field rather than a plain @property so it appears
    # in model_dump output - the @tool wrapper returns list[OWASPEntry] direct
    # and the agent sees the cheatsheetseries.owasp.org URL it cites.
    @computed_field  # type: ignore[prop-decorator]
    @property
    def url(self) -> str:
        return f"{_BASE_URL}/{self.topic}_Cheat_Sheet.html"


__all__ = ["OWASPEntry"]
