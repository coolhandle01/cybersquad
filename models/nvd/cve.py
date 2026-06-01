"""
models.nvd.cve - the NVD CVE record shape, returned by VR's NVD CVE Lookup.

The external-vocabulary record the VR pulls during triage via a live NVD
query (the ``models.mitre.CWE`` type enriches the ``cwe_ids`` this carries).
"""

from __future__ import annotations

from pydantic import BaseModel


class CveEntry(BaseModel):
    """One NVD CVE record, returned by NVD CVE Lookup."""

    id: str
    cvss_score: float | None = None
    cvss_vector: str | None = None
    description: str = ""
    # CWE ids NVD attributes to this CVE (its ``weaknesses``). This is the
    # authoritative CPE -> CVE -> CWE link: the weakness comes from NVD's data,
    # not from an agent guessing. NVD's non-numeric placeholders
    # ("NVD-CWE-noinfo" / "NVD-CWE-Other") are dropped, so an empty list means
    # NVD assigned no concrete CWE.
    cwe_ids: list[int] = []
