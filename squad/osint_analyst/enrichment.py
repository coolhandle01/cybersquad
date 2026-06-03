"""
squad/osint_analyst/enrichment.py - the OSINT post-sweep pivot surface.

Where ``discovery.py`` answers "what is the attack surface" (the sweep
and the slicers over it), this module carries the tools the OA reaches
for *after* the sweep to enrich and pivot on what it surfaced:

- ``Lookup IP Assets`` - ASN + RDAP + PTR for IPs the sweep surfaced,
  composed into the faithful OAM ``IpEnrichment`` subgraph (IPAddress /
  Netblock / AutonomousSystem nodes + registry / registrant assets + edges).

These are the "explore, don't just record" half: the sweep records the
surface; these tools let the agent follow a thread off it with
judgement. The ``recon-flow`` skill steers when to reach for each.

No scope filter on the IP-rooted lookups: the programme scope model is
FQDN-shaped, and the IPs the agent passes were surfaced (and
scope-filtered) by the sweep upstream. The filtering lives at the FQDN
boundary, not the IP one - see the per-tool notes below.
"""

from pydantic import BaseModel, Field

from models import IpAddr, IpEnrichment, RegistrantBundle, Service
from models.primitives import FQDN
from models.scanner import NmapMode, NmapScripts
from squad import cyber_tool
from tools.recon.ip_enrichment import compose_ip_enrichment
from tools.recon.nmap import nmap_scan, services_from_nmap
from tools.recon.rdap import lookup_rdap_for_asn
from tools.recon.rdap_assets import registrant_assets_from_rdap
from tools.recon.scope import TargetFQDN
from tools.recon_host_store import (
    save_host_product_releases,
    save_host_products,
    save_host_relations,
    save_host_services,
)


class _LookupIpAssetsArgs(BaseModel):
    """Explicit args_schema for the Lookup IP Assets tool."""

    ips: list[IpAddr] = Field(
        description=(
            "IPv4 / IPv6 addresses surfaced by the sweep (e.g. the"
            " resolved IPs behind in-scope hostnames, or traceroute"
            " hops worth enriching). Each is validated as an IP address;"
            " a hostname where an IP was expected rejects upstream"
            " (resolve it first via the sweep). Pass the IPs the sweep"
            " already surfaced - this tool does not discover new IPs, it"
            " enriches known ones. Duplicates dedupe."
        ),
    )


@cyber_tool("Lookup IP Assets", args_schema=_LookupIpAssetsArgs)
def lookup_ip_assets_tool(ips: list[IpAddr]) -> IpEnrichment:
    """
    Enrich a set of IPs with ASN, RDAP, and reverse-DNS (PTR) data,
    returning the faithful OAM ``IpEnrichment`` subgraph. This is the
    IP-rooted pivot: given IPs the sweep surfaced, find the netblock /
    AS-owner (Team Cymru), the registrant org + abuse contact (RDAP), and
    the hostnames that PTR back to each IP.

    Fires outbound lookups per IP: Team Cymru bulk-whois (ASN), RDAP HTTP
    fetches (registrant, per IP and per AS), and a dnsx ``-ptr`` reverse
    query. Each source degrades independently - an IP with only ASN data
    still yields its ``IPAddress`` / ``Netblock`` / ``AutonomousSystem``
    nodes rather than being dropped.

    Returns an ``IpEnrichment`` bundle: ``ip_addresses`` / ``netblocks`` /
    ``autonomous_systems`` nodes, the ``autnum_records`` / ``ipnet_records``
    registry records, the registrant ``organizations`` / ``identifiers``
    (abuse + registrant emails), and the ``relations`` joining them
    (``contains`` / ``announces`` / ``managed_by`` / ``registrant_org`` /
    ``ptr_record``). Empty bundle on empty input. PTR-discovered hostnames
    ride in on the ``ptr_record`` edges and are out-of-scope by default -
    pivot evidence, not in-scope assets, until the annotation pass promotes
    any that share the programme's apex.
    """
    return compose_ip_enrichment(ips)


class _LookupRdapAsnArgs(BaseModel):
    """Explicit args_schema for the Lookup RDAP for ASN tool."""

    asn: int = Field(
        ge=0,
        le=4_294_967_295,  # 32-bit ASN range per RFC 6793
        description=(
            "Autonomous System Number to look up, as a bare integer (e.g."
            " 13335 for Cloudflare) - no ``AS`` prefix; a non-numeric"
            " string rejects upstream. Read it off an"
            " ``autonomous_systems`` entry surfaced by Lookup IP Assets."
            " Out-of-range values"
            " (negative, or above the 32-bit ceiling) reject at the"
            " boundary."
        ),
    )


@cyber_tool("Lookup RDAP for ASN", args_schema=_LookupRdapAsnArgs)
def lookup_rdap_asn_tool(asn: int) -> RegistrantBundle:
    """
    Look up the RDAP (RFC 7483) registration for one ASN and return the
    faithful OAM registration subgraph: the ``AutnumRecord`` registry record,
    the registrant ``Organization``, and the abuse / registrant contact
    ``Identifier`` (email) assets, joined by ``registrant_org`` / ``managed_by``
    / ``<role>_email`` edges. This is the ASN-side pivot - IP-side RDAP already
    rides in on ``Lookup IP Assets`` (its ``ipnet_records`` /
    ``organizations``), so reach for this when the question is about the AS
    itself: who to disclose to, or building a pattern-of-life view of an org's
    address space.

    Fires one RDAP HTTP fetch against the authoritative RIR (resolved via the
    IANA bootstrap registry). Returns a ``RegistrantBundle`` ({organizations,
    autnum_records, ipnet_records, identifiers, relations}); the bundle is empty
    when the bootstrap has no entry for the ASN or the RIR lookup fails - the OA
    keeps moving rather than blocking on a miss.
    """
    record = lookup_rdap_for_asn(asn)
    return registrant_assets_from_rdap([record] if record is not None else [], ip_to_cidr={})


class _DiscoverHostServicesArgs(BaseModel):
    """Explicit args_schema for the Discover Host Services tool."""

    host: TargetFQDN = Field(
        description=(
            "A single in-scope hostname to deep-scan, validated as an RFC"
            " 1123 hostname (URLs / ports / paths reject upstream). This is"
            " the commit-to-one target: an out-of-scope host raises rather"
            " than being silently dropped, since deep-scanning is louder"
            " than a passive lookup. Pick a host the sweep already surfaced"
            " whose open-port map shows a non-HTTP service worth a focused"
            " service / banner scan."
        ),
    )
    ports: list[int] = Field(
        description=(
            "The known-open ports to focus the scan on - read them off the"
            " sweep's open-port map for this host. The scan runs ``-sV``"
            " (service / version detection) against exactly these ports"
            " rather than re-sweeping the top-100, so pass the ports the"
            " sweep already found open. An empty list falls back to the"
            " mode's default breadth."
        ),
    )


@cyber_tool("Discover Host Services", args_schema=_DiscoverHostServicesArgs)
def discover_host_services_tool(host: FQDN, ports: list[int]) -> list[Service]:
    """
    Run a focused nmap service / version scan (``-sV`` plus the default
    NSE script category, ``-sC``) against one host's known-open ports.
    This is the naabu-then-nmap second leg: the sweep's quick port scan
    found *which* ports are open; this finds *what is listening* on them -
    service names, version banners, and the NIST CPE nmap matched per
    service.

    The host is scope-filtered at the args_schema boundary; an
    out-of-scope host never reaches this body. Reach for this when the
    sweep's open-port map shows a non-HTTP service (a database port, an
    SSH / RDP / SMTP banner worth fingerprinting) on an in-scope host -
    the HTTP surface is already covered by ``Discover Webpages`` / httpx.

    Returns the host's open ``Service`` assets (one per open port nmap
    fingerprinted), each carrying its banner in ``output`` / ``attributes``.
    Empty list when nmap found nothing (host down / scan blocked) - the OA
    always gets a typed result back. Alongside the return, the full OAM
    subgraph is written to the host directory: ``services.json``, the
    ``products.json`` / ``product_releases.json`` nmap's CPEs decomposed to,
    and the ``port`` / ``product_used`` edges in ``relations.json`` - the
    on-disk form of what #45 upserts. The raw nmap XML is not persisted -
    this is a focused pivot, not an evidence artefact.
    """
    result = nmap_scan(
        [host],
        mode=NmapMode.SERVICE_VERSION,
        scripts=NmapScripts.DEFAULT,
        persist_evidence=False,
        ports=ports,
    )
    host_result = next((h for h in result.hosts if h.host == host), None)
    if host_result is None:
        # nmap surfaced no row for the queried host (down / blocked /
        # parse miss) - fall back to the first row if any, else nothing.
        host_result = result.hosts[0] if result.hosts else None
    if host_result is None:
        return []
    assets = services_from_nmap(host_result)
    # Persist each OAM facet to the host directory - the on-disk form of what
    # #45 upserts (assets + their attached properties) and inserts
    # (relations.json edges). Presence graph: skip the empty writes.
    if assets.services:
        save_host_services(host, assets.services)
    if assets.products:
        save_host_products(host, assets.products)
    if assets.product_releases:
        save_host_product_releases(host, assets.product_releases)
    if assets.relations:
        save_host_relations(host, assets.relations)
    return assets.services


__all__ = [
    "_DiscoverHostServicesArgs",
    "_LookupIpAssetsArgs",
    "_LookupRdapAsnArgs",
    "discover_host_services_tool",
    "lookup_ip_assets_tool",
    "lookup_rdap_asn_tool",
]
