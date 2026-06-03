"""Decompose dnsx forward-resolution records into their OAM subgraph.

Each A / CNAME answer dnsx returns for a host becomes two faithful OAM facts: a
``DNSRecordProperty`` hung off the host's ``FQDN`` node (the record's *content*)
and a ``BasicDNSRelation`` edge from that FQDN to the answer asset (the IP for
an A record, the target FQDN for a CNAME). The DNS-layer analogue of
``services_from_nmap``: assets carry their attached properties, the relations
are the explicit edges ``relations.json`` holds.
"""

from __future__ import annotations

from typing import NamedTuple

from models import DNSRecordProperty, Relation, RelationType, RRHeader
from tools.recon.dnsx import DNSRecord

# DNS numeric resource-record type codes (IANA / RFC 1035) and the IN class.
_RR_TYPE_A = 1
_RR_TYPE_CNAME = 5
_RR_CLASS_IN = 1


class DnsAssets(NamedTuple):
    """The OAM subgraph one host's dnsx forward records decompose into.

    ``records`` are the ``DNSRecordProperty`` entries (the record content hung
    off the FQDN node); ``relations`` are the ``BasicDNSRelation`` edges to the
    answer assets that ``relations.json`` holds.
    """

    records: list[DNSRecordProperty]
    relations: list[Relation]


def dns_assets_from_dnsx(records: list[DNSRecord]) -> DnsAssets:
    """Decompose dnsx forward records into their OAM property + relation subgraph.

    One ``DNSRecordProperty`` and one ``BasicDNSRelation`` per A answer
    (rr_type 1, edge ``a_record``: FQDN -> IP) and per CNAME answer (rr_type 5,
    edge ``cname_record``: FQDN -> target). The ``RRHeader`` carries dnsx's
    reported response ``ttl`` (one value per host response, so the host's A /
    CNAME answers share it).
    """
    properties: list[DNSRecordProperty] = []
    relations: list[Relation] = []
    for record in records:
        for ip in record.a_records:
            header = RRHeader(rr_type=_RR_TYPE_A, rr_class=_RR_CLASS_IN, ttl=record.ttl)
            properties.append(
                DNSRecordProperty(property_name=record.hostname, header=header, data=ip)
            )
            relations.append(
                Relation(
                    relation_type=RelationType.BASIC_DNS,
                    label="a_record",
                    from_key=record.hostname,
                    to_key=ip,
                    header=header,
                )
            )
        for cname in record.cname:
            header = RRHeader(rr_type=_RR_TYPE_CNAME, rr_class=_RR_CLASS_IN, ttl=record.ttl)
            properties.append(
                DNSRecordProperty(property_name=record.hostname, header=header, data=cname)
            )
            relations.append(
                Relation(
                    relation_type=RelationType.BASIC_DNS,
                    label="cname_record",
                    from_key=record.hostname,
                    to_key=cname,
                    header=header,
                )
            )
    return DnsAssets(properties, relations)


__all__ = ["DnsAssets", "dns_assets_from_dnsx"]
