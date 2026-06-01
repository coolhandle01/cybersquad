"""
models.mitre.cwe - typed shape for a Common Weakness Enumeration entry.

Lives in the MITRE domain package alongside the weakness-taxonomy shapes. The
fields are sourced from the bundled MITRE corpus via ``tools/cwe_data.py``
(name + description, keyed by id); this module is just the row contract
consumers import to type-check return shapes against.
"""

from __future__ import annotations

from pydantic import BaseModel, computed_field


class CWEEntry(BaseModel):
    """A single CWE entry: id, MITRE name + description, and the MITRE URL."""

    cwe_id: int
    name: str
    description: str

    # Exposed as a computed_field rather than a plain @property so it appears
    # in model_dump output - the @tool wrapper returns the CWEEntry direct and
    # the agent sees the MITRE URL it cites in the remediation section.
    @computed_field  # type: ignore[prop-decorator]
    @property
    def url(self) -> str:
        return f"https://cwe.mitre.org/data/definitions/{self.cwe_id}.html"


__all__ = ["CWEEntry"]
