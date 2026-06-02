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


class ServiceCves(BaseModel):
    """The CVEs NVD returned for one of a host's nmap-detected service CPEs.

    One row of the VR's CVEs for Host lookup: the ``Service`` whose CPE was
    queried, the exact CPE 2.3 name fed to NVD, and the CVEs whose
    applicability criteria cover it (each carrying NVD's own ``cwe_ids`` - the
    authoritative CPE -> CVE -> CWE link). The VR turns these into
    ``VulnProperty`` annotations via Annotate Vulnerabilities.
    """

    service_id: str  # the Service.id the CPE came from ("<host>:<port>/<proto>")
    cpe: str  # the CPE 2.3 name nmap matched and NVD was queried for
    cves: list[CveEntry]
