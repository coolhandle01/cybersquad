"""
models.nvd.cve - the NVD CVE record shape, returned by the VR's CVE lookups.

A flat record of what NVD returned - no enrichment baked in. ``cwe_ids`` carries
the raw weakness ids NVD attributed; resolving them to named ``CWE`` entries (the
``models.mitre`` corpus) happens at the boundary that needs it - the tool layer's
``vuln_from_cve`` for the OAM ``VulnProperty`` category, or the agent's id-based
``Lookup CWE`` tool - so this leaf stays free of a ``models.nvd -> models.mitre``
dependency and does no corpus lookup on serialisation.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, computed_field

# Boundary cap on the NVD-sourced description (see the field comment below).
# Exported so the parser (``tools.nvd._parse_cve``) truncates to the same
# length rather than letting an over-long upstream description reject the CVE -
# one source of truth for the cap, used at the model and at the parse boundary.
DESCRIPTION_MAX_LENGTH = 2000


class CVE(BaseModel):
    """One NVD CVE record, returned by NVD CVE Lookup / List CVEs for CPE."""

    id: str
    cvss_score: float | None = None
    cvss_vector: str | None = None
    # Tool-captured from the NVD feed (external source), not agent-authored,
    # and this model is the direct return of the VR's CVE-lookup tools - so the
    # text reaches the agent's context. Defence (cybersquad-models skill,
    # tool-captured text): a boundary length cap so a poisoned upstream
    # description cannot smuggle a large injection into context. Mirrors the
    # cap on the persisted ``VulnProperty.description``.
    description: str = Field(default="", max_length=DESCRIPTION_MAX_LENGTH)
    # CWE ids NVD attributes to this CVE (its ``weaknesses``). This is the
    # authoritative CPE -> CVE -> CWE link: the weakness comes from NVD's data,
    # not from an agent guessing. NVD's non-numeric placeholders
    # ("NVD-CWE-noinfo" / "NVD-CWE-Other") are dropped at parse time, so an empty
    # list means NVD assigned no concrete CWE. Carried as raw ids verbatim -
    # name resolution is the consumer's job (``CWE.get`` / ``Lookup CWE``).
    cwe_ids: list[int] = Field(default_factory=list)

    # The canonical NVD detail page for this CVE. A computed_field (not a plain
    # property) so it serialises into model_dump - the @cyber_tool return hands
    # the CVE straight to the agent, which cites this URL. Mirrors ``CWE.url`` /
    # ``OWASPEntry.url``. (Pure string derivation, no cross-domain lookup.)
    @computed_field  # type: ignore[prop-decorator]
    @property
    def url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.id}"
