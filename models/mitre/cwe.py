"""
models.mitre.cwe - the CWE type.

One class for "a CWE": construct it from an id and it validates that the id is a
real weakness by looking it up in the bundled MITRE corpus (the ``cwe2``
library), carrying MITRE's canonical name + description + URL. Validity *is*
corpus membership - there is no separate "id" primitive and "entry" model, and
no hand-maintained data.

Accepts a bare int (``CWE.model_validate(89)``) or a mapping with ``cwe_id``, so
it round-trips through workspace JSON; either way name + description are taken
from the corpus, never trusted from the input. Use ``CWE.get(id)`` for a
None-on-miss lookup at a tool boundary.
"""

from __future__ import annotations

from functools import cache

from cwe2.database import Database, InvalidCWEError
from pydantic import BaseModel, computed_field, model_validator


@cache
def _db() -> Database:
    """The bundled MITRE CWE database, parsed once and reused."""
    return Database()


class CWE(BaseModel):
    """A Common Weakness Enumeration entry, keyed and validated by its id."""

    cwe_id: int
    name: str
    description: str

    @model_validator(mode="before")
    @classmethod
    def _from_corpus(cls, data: object) -> object:
        """Resolve a bare int / ``{"cwe_id": n}`` to the full MITRE record.

        Name + description always come from the corpus, never from the input -
        a CWE is whatever MITRE says it is. An id outside the corpus raises.
        """
        raw = data.get("cwe_id") if isinstance(data, dict) else data
        if not isinstance(raw, int) or isinstance(raw, bool):
            return data  # not an int id - let pydantic raise its normal error
        try:
            weakness = _db().get(raw)
        except InvalidCWEError as exc:
            raise ValueError(f"CWE-{raw} is not a recognised MITRE CWE id") from exc
        return {"cwe_id": raw, "name": weakness.name, "description": weakness.description}

    @classmethod
    def get(cls, cwe_id: int) -> CWE | None:
        """Look up ``cwe_id`` in the corpus, returning None if it is not a real CWE."""
        try:
            return cls.model_validate(cwe_id)
        except ValueError:
            return None

    # Exposed as a computed_field rather than a plain @property so it appears
    # in model_dump output - the @tool wrapper returns the CWE direct and the
    # agent sees the MITRE URL it cites in the remediation section.
    @computed_field  # type: ignore[prop-decorator]
    @property
    def url(self) -> str:
        return f"https://cwe.mitre.org/data/definitions/{self.cwe_id}.html"


__all__ = ["CWE"]
