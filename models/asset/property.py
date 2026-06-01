"""
models.asset.property - the OAM properties hung off asset nodes.

OAM models a fact about an asset - a vulnerability, an arbitrary key/value, a
provenance stamp, a DNS record - not as a standalone asset but as a *property*
attached to the asset node. This module gathers the four OAM property shapes an
asset can carry (amass splits them across its ``general`` and ``dns`` packages;
cybersquad groups them here).

OAM properties:
* ``VulnProperty`` <https://owasp-amass.github.io/docs/open_asset_model/properties/vuln_property/>
* ``DNSRecordProperty`` <https://owasp-amass.github.io/docs/open_asset_model/properties/dns_property/>
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from models.asset.relation import RRHeader


class SimpleProperty(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``SimpleProperty``.

    An arbitrary key/value fact attached to an asset (OAM json tag in
    parentheses): ``property_name`` (``property_name``) and ``property_value``
    (``property_value``). The catch-all OAM uses for asset metadata that has
    no richer typed property of its own.
    """

    property_name: str = Field(min_length=1, max_length=128)  # property_name
    # Agent- / tool-captured value; length-capped at the boundary.
    property_value: str = Field(default="", max_length=2048)  # property_value


class SourceProperty(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``SourceProperty``.

    Provenance: which tool / source produced a fact, and how confident it is
    (OAM json tag in parentheses): ``source`` (``name``) and ``confidence``
    (``confidence``, 0-100). OAM's source-attribution slot, stamped on every
    asset / property an upsert produces.
    """

    source: str = Field(min_length=1, max_length=64)  # name (the tool / feed)
    confidence: int = Field(default=0, ge=0, le=100)  # confidence


class DNSRecordProperty(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``DNSRecordProperty``.

    A DNS resource record OAM hangs off the ``FQDN`` node as a property (the
    record's *content*), complementing the DNS *relations* that model the edge
    to the answer asset. Mirrors amass's ``DNSRecordProperty`` field for field
    (OAM json tag in parentheses):

    * ``property_name`` (``property_name``) -> the record's name / label.
    * ``header`` (``header``) -> the resource-record header (``RRHeader``:
      rr_type / class / ttl), reused from ``models.asset.relation``.
    * ``data`` (``data``) -> the record's RDATA, kept verbatim.
    """

    property_name: str = Field(min_length=1, max_length=255)  # property_name
    header: RRHeader  # header (rr_type / class / ttl)
    # Tool-captured RDATA (the resolver's record value). Defence
    # (cybersquad-models skill, tool-captured text): a boundary length cap; read
    # as data, never re-issued to an LLM as instruction context.
    data: str = Field(default="", max_length=2048)  # data


class VulnProperty(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``VulnProperty``.

    OAM models a vulnerability not as a standalone asset but as a property
    hung off the vulnerable asset (a ``ProductRelease`` / ``Service`` /
    ``FQDN``). Mirrors amass's ``VulnProperty`` field for field (OAM json tag
    in parentheses):

    * ``id`` (``id``) -> the vulnerability identifier, e.g. "CVE-2022-22965".
    * ``description`` (``desc``) -> the human-readable summary.
    * ``source`` (``source``) -> the feed / tool that produced the fact ("nvd").
    * ``category`` (``category``) -> the weakness class (a CWE id / name).
    * ``enumeration`` (``enum``) -> the scheme ``id`` is drawn from: "CVE",
      "CWE", "GHSA".
    * ``reference`` (``ref``) -> a canonical URL for the entry.

    The Vulnerability Researcher attaches these after a CPE -> CVE lookup
    matches a ``ProductRelease`` (nmap's CPE is the source that builds the
    Product / ProductRelease assets and keys the lookup).
    """

    # The vulnerability identifier - "CVE-2022-22965", "CWE-89". Required: the
    # asset's join key into NVD / MITRE. Bare str: a CWE id resolves through
    # the ``CWE`` type, a CVE id through NVD; this field carries either form.
    id: str = Field(min_length=1, max_length=64)

    # Tool-captured from the NVD feed (external source), not agent-authored.
    # Defence (cybersquad-models skill, tool-captured text): a boundary length
    # cap so a poisoned upstream description cannot smuggle a large injection
    # downstream.
    description: str = Field(default="", max_length=2000)

    # Provenance: the feed / tool that produced this fact ("nvd"). A tool-named
    # closed vocabulary, not free external text; length-capped defensively.
    source: str = Field(default="", max_length=32)

    # The weakness class - a CWE id or name where the lookup carried one.
    category: str = Field(default="", max_length=128)

    # The identifier scheme ``id`` is drawn from: "CVE", "CWE", "GHSA".
    enumeration: str = Field(default="", max_length=32)

    # Canonical URL for the entry (the NVD / MITRE page). A capped str rather
    # than HttpUrl because OAM's ``ref`` is an open string that round-trips
    # empty and may carry a non-URL advisory reference.
    reference: str = Field(default="", max_length=255)
