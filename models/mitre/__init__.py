"""
models.mitre - the MITRE weakness-taxonomy vocabulary.

Distinct from the OAM asset graph (``models.asset``) and from NIST's NVD /
CVSS scoring domain (``models.nvd``). Houses the MITRE shapes - currently the
``CWE`` type: one class for a Common Weakness Enumeration entry, validated and
enriched from the bundled MITRE corpus by its id.

Depends on pydantic / stdlib and the ``cwe2`` corpus (the same way
``models.nvd`` depends on the ``cvss`` library), so any model module can import
from it without a cycle.
"""

from __future__ import annotations

from models.mitre.cwe import CWE

__all__ = ["CWE"]
