"""
models.asset.relation - the OAM typed edges between asset nodes.

OAM is a graph: assets are nodes (each carrying its own attached properties),
relations are typed edges. cybersquad persists the edges as a flat record in
``relations.json`` - the shape #45 inserts one graph edge per. An edge names
the two asset ``Key``s it joins (``from_key`` -> ``to_key``), its OAM
``RelationType`` and ``label`` (OAM's ``Name``), plus the type-specific detail
the richer OAM relations carry (the port for a ``PortRelation``, the DNS
``RRHeader`` for the DNS relations).

OAM relations:
<https://owasp-amass.github.io/docs/open_asset_model/>
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class RelationType(StrEnum):
    """The OAM relation kinds (amass ``RelationType`` constants)."""

    SIMPLE = "SimpleRelation"
    PORT = "PortRelation"
    BASIC_DNS = "BasicDNSRelation"
    PREF_DNS = "PrefDNSRelation"
    SRV_DNS = "SRVDNSRelation"


class RRHeader(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``RRHeader``.

    The DNS resource-record header a DNS relation carries (OAM json tag in
    parentheses): ``rr_type`` (``rr_type``), ``rr_class`` (``class`` - renamed
    off the Python keyword), ``ttl`` (``ttl``).
    """

    rr_type: int = Field(ge=0)  # rr_type
    rr_class: int = Field(default=0, ge=0)  # class (renamed off the Python keyword)
    ttl: int = Field(default=0, ge=0)  # ttl


class Relation(BaseModel):
    """A persisted OAM edge - one row of ``relations.json``.

    The graph edge between two assets. ``from_key`` / ``to_key`` are the
    endpoints' OAM ``Key``s; ``relation_type`` + ``label`` are the OAM
    ``RelationType`` and ``Name``. The remaining fields are the type-specific
    detail OAM's richer relations carry, populated only for the matching
    ``relation_type``:

    * ``PortRelation`` (host -> ``Service``): ``port_number`` + ``protocol``.
    * the DNS relations: ``header`` (``RRHeader``), plus ``preference``
      (``PrefDNSRelation`` / MX) and ``priority`` / ``weight`` / ``port``
      (``SRVDNSRelation``).

    ``SimpleRelation`` (``product_used`` / ``certificate`` / ...) carries no
    extra detail - just type + label + endpoints. #45 maps each record onto
    the matching amass relation struct as it writes the edge to the graph DB.
    """

    relation_type: RelationType
    label: str = Field(min_length=1, max_length=64)  # OAM ``Name``
    from_key: str = Field(min_length=1, max_length=512)  # source asset Key
    to_key: str = Field(min_length=1, max_length=512)  # target asset Key

    # PortRelation detail.
    port_number: int | None = Field(default=None, ge=1, le=65535)
    protocol: str = Field(default="", max_length=8)  # "tcp" / "udp"

    # DNS relation detail (BasicDNSRelation / PrefDNSRelation / SRVDNSRelation).
    header: RRHeader | None = None
    preference: int | None = Field(default=None, ge=0)  # PrefDNSRelation (MX)
    priority: int | None = Field(default=None, ge=0)  # SRVDNSRelation
    weight: int | None = Field(default=None, ge=0)  # SRVDNSRelation
    srv_port: int | None = Field(default=None, ge=0, le=65535)  # SRVDNSRelation port
