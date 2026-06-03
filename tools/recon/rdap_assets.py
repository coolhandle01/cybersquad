"""Decompose RDAP registrant lookups into their OAM asset subgraph.

RDAP answers "who owns this resource". This decomposes the recon-internal
``RdapRecord`` parse shape into faithful OAM assets - the analogue of
``services_from_nmap`` for the registration layer:

* an RDAP-by-ASN record yields an ``AutnumRecord`` (the AS registry record) and
  a ``managed_by`` edge from the ``AutonomousSystem`` to the registrant;
* an RDAP-by-IP record yields an ``IPNetRecord`` (the IP-block registry record).
  RDAP-by-IP does not return the block's CIDR, so it is **correlated** from the
  Cymru netblock the IP sits in (the ``ip_to_cidr`` map) - a faithful
  ``IPNetRecord`` needs its ``cidr``.

Both yield the registrant ``Organization`` and the contact emails as
``Identifier`` assets, joined by the spec relation labels (``registrant_org`` /
``managed_by`` / ``<role>_email``).
"""

from __future__ import annotations

from models import (
    AutnumRecord,
    Identifier,
    IPNetRecord,
    Organization,
    RegistrantBundle,
    Relation,
    RelationType,
)
from models.asset.network import RdapRecord


def _asn_from_query(query: str) -> int | None:
    """Parse the ASN out of an RDAP autnum query ("AS15169" -> 15169).

    Returns ``None`` for an IP-network query (the IP-block branch handles it)
    or a mis-shaped value.
    """
    if query.startswith("AS") and query[2:].isdigit():
        return int(query[2:])
    return None


def registrant_assets_from_rdap(
    rdap_records: list[RdapRecord],
    ip_to_cidr: dict[str, str],
) -> RegistrantBundle:
    """Decompose RDAP records into the OAM registration subgraph.

    Per record: an ``AutnumRecord`` (AS query, keyed by number) or an
    ``IPNetRecord`` (IP query, CIDR correlated from ``ip_to_cidr`` - skipped if
    the IP has no known netblock), the registrant ``Organization`` (by name),
    and an ``Identifier`` per contact email. Edges: ``registrant_org`` (registry
    record -> Organization), ``managed_by`` (AutonomousSystem -> Organization,
    AS records only), and ``<role>_email`` from the registrant (or the registry
    record when no org) to each email. All de-duplicated by identity.
    """
    organizations: dict[str, Organization] = {}
    autnum_by_number: dict[int, AutnumRecord] = {}
    ipnet_by_cidr: dict[str, IPNetRecord] = {}
    identifiers: dict[str, Identifier] = {}
    relations: list[Relation] = []

    for rec in rdap_records:
        asn = _asn_from_query(rec.query)
        if asn is not None:
            autnum_by_number.setdefault(asn, AutnumRecord(number=asn, handle=rec.handle or ""))
            record_key = rec.handle or f"AS{asn}"
            managed_subject: str | None = f"AS{asn}"
        else:
            cidr = ip_to_cidr.get(rec.query)
            if cidr is None:
                # No netblock for this IP (Cymru miss): an IPNetRecord needs a
                # cidr, so skip rather than fabricate one.
                continue
            ipnet_by_cidr.setdefault(cidr, IPNetRecord(cidr=cidr, handle=rec.handle or ""))
            record_key = rec.handle or cidr
            managed_subject = None  # managed_by is an AS -> Org edge only

        org_key: str | None = None
        if rec.registrant_organisation:
            org = organizations.setdefault(
                rec.registrant_organisation,
                Organization(name=rec.registrant_organisation),
            )
            org_key = org.name
            relations.append(
                Relation(
                    relation_type=RelationType.SIMPLE,
                    label="registrant_org",
                    from_key=record_key,
                    to_key=org_key,
                )
            )
            if managed_subject is not None:
                relations.append(
                    Relation(
                        relation_type=RelationType.SIMPLE,
                        label="managed_by",
                        from_key=managed_subject,
                        to_key=org_key,
                    )
                )

        anchor = org_key or record_key
        for contact in rec.contacts:
            if contact.email:
                ident = identifiers.setdefault(
                    contact.email, Identifier(id=contact.email, id_type="email")
                )
                relations.append(
                    Relation(
                        relation_type=RelationType.SIMPLE,
                        label=f"{contact.role.value}_email",
                        from_key=anchor,
                        to_key=ident.id,
                    )
                )

    return RegistrantBundle(
        organizations=list(organizations.values()),
        autnum_records=list(autnum_by_number.values()),
        ipnet_records=list(ipnet_by_cidr.values()),
        identifiers=list(identifiers.values()),
        relations=relations,
    )


__all__ = ["registrant_assets_from_rdap"]
