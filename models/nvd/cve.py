"""
models.nvd.cve - the NVD CVE record shape, returned by the VR's CVE lookups.

The external-vocabulary record the VR pulls via a live NVD query. ``cwe_ids``
carries the raw NVD weakness ids; ``cwes`` resolves them through the
``models.mitre.CWE`` corpus so the agent sees the named weakness and its MITRE
URL alongside the CVE. The ``models.nvd`` -> ``models.mitre`` edge this adds is
acyclic: ``mitre`` imports nothing from ``models`` but its own corpus.
"""

from __future__ import annotations

from pydantic import BaseModel, computed_field

from models.mitre import CWE


class CVE(BaseModel):
    """One NVD CVE record, returned by NVD CVE Lookup / List CVEs for CPE."""

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

    # The canonical NVD detail page for this CVE. A computed_field (not a plain
    # property) so it serialises into model_dump - the @cyber_tool return hands
    # the CVE straight to the agent, which cites this URL. Mirrors ``CWE.url`` /
    # ``OWASPEntry.url``.
    @computed_field  # type: ignore[prop-decorator]
    @property
    def url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.id}"

    # The weaknesses NVD attributes to this CVE, resolved from ``cwe_ids``
    # through the MITRE corpus so each carries its name / description / URL.
    # computed_field for the same reason as ``url``: the agent sees the named
    # CWEs in the tool output, not bare ints. Ids outside the corpus are dropped
    # (``CWE.get`` -> None), matching the "concrete CWE only" stance of
    # ``cwe_ids``.
    @computed_field  # type: ignore[prop-decorator]
    @property
    def cwes(self) -> list[CWE]:
        return [cwe for cwe_id in self.cwe_ids if (cwe := CWE.get(cwe_id)) is not None]
