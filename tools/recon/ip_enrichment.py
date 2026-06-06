"""tools/recon/ip_enrichment.py - compose the IP-rooted OAM subgraph.

The faithful replacement for the legacy ``compose_ip_assets`` / ``IpAsset``
path. Runs the per-IP lookups (Cymru ASN, dnsx PTR, RDAP registrant) and feeds
their recon-internal parse rows through the decomposition producers
(``compose_ip_graph`` for the routing spine + PTR, ``registrant_assets_from_rdap``
for the registration layer), gathering the faithful OAM assets and their
``Relation`` edges into one ``IpEnrichment`` bundle.

Each lookup degrades independently: a missing ASN / RDAP / PTR result thins the
subgraph rather than failing it - an IP with only ASN data still yields its
``IPAddress`` + ``Netblock`` + ``AutonomousSystem`` nodes.
"""

from __future__ import annotations

import logging

from models import IpEnrichment
from models.primitives import IpAddr
from tools.recon.asn import lookup_asn
from tools.recon.dnsx import resolve_ptr
from tools.recon.ip_graph import compose_ip_graph
from tools.recon.rdap import lookup_rdap_for_asn, lookup_rdap_for_ip
from tools.recon.rdap_assets import registrant_assets_from_rdap

logger = logging.getLogger(__name__)


def compose_ip_enrichment(ips: list[IpAddr], *, with_rdap: bool = True) -> IpEnrichment:
    """Build the ``IpEnrichment`` subgraph for a set of IPs.

    ``with_rdap=False`` skips the per-IP / per-ASN RDAP HTTP fetches when the OA
    wants the cheap ASN+PTR enrichment without paying for the registrant detail
    (RDAP is per-resource HTTP; Cymru / PTR batch). Defaults True so the full
    enrichment is the cheap-default opt-out.

    Returns an empty ``IpEnrichment`` for empty input. The IPs are
    de-duplicated; per-lookup failures degrade the subgraph rather than raising.
    """
    if not ips:
        return IpEnrichment()

    unique = list(dict.fromkeys(ips))
    asn_records = lookup_asn(unique)
    ptr_records = resolve_ptr(unique)
    graph = compose_ip_graph(asn_records, ptr_records)

    # The Netblock a faithful IPNetRecord needs its cidr from: the "contains"
    # edge keys the netblock cidr against the IP it holds.
    ip_to_cidr = {r.to_key: r.from_key for r in graph.relations if r.label == "contains"}

    rdap_records = []
    if with_rdap:
        for ip in unique:
            record = lookup_rdap_for_ip(ip)
            if record is not None:
                rdap_records.append(record)
        for asn in {a.number for a in graph.autonomous_systems}:
            record = lookup_rdap_for_asn(asn)
            if record is not None:
                rdap_records.append(record)
    registrant = registrant_assets_from_rdap(rdap_records, ip_to_cidr)

    enrichment = IpEnrichment(
        ip_addresses=graph.addresses,
        netblocks=graph.netblocks,
        autonomous_systems=graph.autonomous_systems,
        autnum_records=registrant.autnum_records,
        ipnet_records=registrant.ipnet_records,
        organizations=registrant.organizations,
        identifiers=registrant.identifiers,
        relations=graph.relations + registrant.relations,
    )
    logger.info(
        "composed IpEnrichment: %d IPs, %d netblocks, %d AS, %d orgs, %d edges",
        len(enrichment.ip_addresses),
        len(enrichment.netblocks),
        len(enrichment.autonomous_systems),
        len(enrichment.organizations),
        len(enrichment.relations),
    )
    return enrichment


__all__ = ["compose_ip_enrichment"]
