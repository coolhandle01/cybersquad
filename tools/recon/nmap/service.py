"""Decompose a scanner-internal ``NmapHostResult`` into its OAM subgraph.

This is the OA tool boundary. ``NmapService`` is scanner plumbing (it mirrors
nmap's raw ``<port>`` / ``<service>`` XML, including the port state); the OAM
side is a small graph: one ``Service`` asset per open port, the ``Product`` /
``ProductRelease`` assets nmap's CPE decomposes into, and the typed relations
that join them (``port``: host -> Service; ``product_used``: Service ->
ProductRelease). Only *open* services become nodes - OAM is a presence graph,
so a filtered / closed port is absence, not a node.

The CPE is the source: nmap matches ``cpe:2.3:a:nginx:nginx:1.25.3``, which
``product_release_from_cpe`` turns into the ``Product`` / ``ProductRelease``
assets, and which the VR later keys its CVE lookup on to hang ``VulnProperty``
off the release.
"""

from __future__ import annotations

from typing import NamedTuple

from models import Product, ProductRelease, Relation, RelationType, Service, SourceProperty
from models.scanner import NmapHostResult
from tools.cpe import product_release_from_cpe

# nmap reports a 1-10 service-detection confidence per match (NmapService.conf);
# the OAM SourceProperty.confidence is 0-100, so scale by 10 when stamping.
_NMAP_SOURCE = "nmap"
_NMAP_CONF_SCALE = 10


class NmapAssets(NamedTuple):
    """The OAM subgraph one nmap host result decomposes into.

    The assets carry their own attached properties (``Service.vulns`` etc.);
    the ``relations`` are the explicit edges that ``relations.json`` holds.
    """

    services: list[Service]
    products: list[Product]
    product_releases: list[ProductRelease]
    relations: list[Relation]


def services_from_nmap(result: NmapHostResult) -> NmapAssets:
    """Decompose an ``NmapHostResult`` into its open-service OAM subgraph.

    Each open ``NmapService`` becomes one ``Service`` asset (identity
    ``<host>:<port>/<protocol>``, the banner in ``output`` / ``attributes``),
    a ``port`` relation from the host to it, and - when nmap matched a CPE -
    the ``Product`` / ``ProductRelease`` assets the CPE decomposes into plus a
    ``product_used`` relation to the release. Products / releases are
    de-duplicated by name across the host's services.
    """
    services: list[Service] = []
    products: dict[str, Product] = {}
    releases: dict[str, ProductRelease] = {}
    relations: list[Relation] = []

    for svc in result.services:
        if svc.state != "open":
            continue
        service_id = f"{result.host}:{svc.port}/{svc.protocol}"
        output = svc.extra_info or ""
        attributes: dict[str, list[str]] = {}
        if svc.product:
            attributes["product"] = [svc.product]
        if svc.version:
            attributes["version"] = [svc.version]
        if svc.cpe:
            attributes["cpe"] = [svc.cpe]

        services.append(
            Service(
                id=service_id,
                type=svc.service or "",
                output=output,
                output_length=len(output),
                attributes=attributes,
                sources=[
                    SourceProperty(source=_NMAP_SOURCE, confidence=svc.conf * _NMAP_CONF_SCALE)
                ],
            )
        )
        relations.append(
            Relation(
                relation_type=RelationType.PORT,
                label="port",
                from_key=str(result.host),
                to_key=service_id,
                port_number=svc.port,
                protocol=svc.protocol,
            )
        )

        if svc.cpe and (decomposed := product_release_from_cpe(svc.cpe)) is not None:
            product, release = decomposed
            nmap_source = SourceProperty(
                source=_NMAP_SOURCE, confidence=svc.conf * _NMAP_CONF_SCALE
            )
            product.sources = [nmap_source]
            release.sources = [nmap_source]
            products.setdefault(product.name, product)
            releases.setdefault(release.name, release)
            relations.append(
                Relation(
                    relation_type=RelationType.SIMPLE,
                    label="product_used",
                    from_key=service_id,
                    to_key=release.name,
                )
            )

    return NmapAssets(services, list(products.values()), list(releases.values()), relations)


__all__ = ["NmapAssets", "services_from_nmap"]
