"""
models.asset.ip - the ``IpEnrichment`` bundle: the IP-rooted OAM subgraph.

The OSINT Analyst's IP enrichment pass (Cymru ASN, RDAP registrant, dnsx PTR)
produces a set of faithful OAM assets - ``IPAddress`` / ``Netblock`` /
``AutonomousSystem`` nodes, the ``AutnumRecord`` / ``IPNetRecord`` registry
records, the registrant ``Organization`` and contact ``Identifier`` assets -
joined by typed ``Relation`` edges. This bundle carries that subgraph as one
typed return, the IP-layer counterpart to ``AttackGraph`` for the web layer.

Replaces the legacy ``IpAsset`` composition (which nested the raw Cymru / RDAP
parse rows per IP): the producers in ``tools/recon`` now decompose those rows
into the faithful assets above, and this bundle gathers them.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from models.asset.identifier import Identifier
from models.asset.network import AutonomousSystem, IPAddress, Netblock
from models.asset.org import Organization
from models.asset.registration import AutnumRecord, IPNetRecord
from models.asset.relation import Relation


class IpEnrichment(BaseModel):
    """The IP-rooted OAM subgraph the OA's enrichment pass produces.

    The asset nodes plus the ``Relation`` edges that join them (``contains`` /
    ``announces`` / ``managed_by`` / ``registrant_org`` / ``<role>_email`` /
    ``ptr_record``). All lists default empty - an enrichment pass is useful with
    whatever subset of Cymru / RDAP / PTR data returned.
    """

    ip_addresses: list[IPAddress] = Field(default_factory=list)
    netblocks: list[Netblock] = Field(default_factory=list)
    autonomous_systems: list[AutonomousSystem] = Field(default_factory=list)
    autnum_records: list[AutnumRecord] = Field(default_factory=list)
    ipnet_records: list[IPNetRecord] = Field(default_factory=list)
    organizations: list[Organization] = Field(default_factory=list)
    identifiers: list[Identifier] = Field(default_factory=list)
    relations: list[Relation] = Field(default_factory=list)


class RegistrantBundle(BaseModel):
    """The OAM registration subgraph an RDAP lookup decomposes into.

    The registry records (``AutnumRecord`` / ``IPNetRecord``), the registrant
    ``Organization``, and the contact ``Identifier`` assets, plus the
    ``registrant_org`` / ``managed_by`` / ``<role>_email`` edges joining them -
    the registration-layer counterpart to ``IpEnrichment``. The OA's ``Lookup
    RDAP for ASN`` tool returns it, and ``compose_ip_enrichment`` folds it into
    the ``IpEnrichment`` bundle.
    """

    organizations: list[Organization] = Field(default_factory=list)
    autnum_records: list[AutnumRecord] = Field(default_factory=list)
    ipnet_records: list[IPNetRecord] = Field(default_factory=list)
    identifiers: list[Identifier] = Field(default_factory=list)
    relations: list[Relation] = Field(default_factory=list)
