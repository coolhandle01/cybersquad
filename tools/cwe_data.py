"""
tools/cwe_data.py - CWE enrichment from the bundled MITRE corpus.

A thin wrapper over the ``cwe2`` library (the full MITRE CWE database, bundled
offline): given a CWE id, return its MITRE name + description. No catalogue, no
alias index, no curated prose - nothing hand-maintained.

The id is supplied by the caller. For CVE/service findings it comes from
``NVD CVE Lookup`` (``CveEntry.cwe_ids`` - NVD's own weakness attribution); the
agent enriches that id here to cite MITRE's canonical wording in a report.
"""

from __future__ import annotations

from functools import cache

from cwe2.database import Database, InvalidCWEError

# CWEEntry lives in models/mitre/ per the typed-shapes-live-in-models
# rule. Re-exported here so existing ``from tools.cwe_data import
# CWEEntry`` consumers keep working; the canonical import path is
# ``from models import CWEEntry``.
from models.mitre import CWEEntry


@cache
def _db() -> Database:
    """The bundled MITRE CWE database, parsed once and reused."""
    return Database()


def get_by_id(cwe_id: int) -> CWEEntry | None:
    """Enrich ``cwe_id`` from the bundled MITRE corpus (name + description).

    Returns None if ``cwe_id`` is not a real CWE. Any valid CWE id resolves -
    the agent can cite any weakness in the corpus, not a curated subset.
    """
    try:
        weakness = _db().get(cwe_id)
    except InvalidCWEError:
        return None
    return CWEEntry(cwe_id=cwe_id, name=weakness.name, description=weakness.description)
