"""
tools/recon - OSINT and reconnaissance tooling for the OSINT Analyst.

External binaries required: subfinder, httpx (CLI), nmap, waybackurls, testssl.sh
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from models import AttackGraph, Endpoint
from models.h1 import Programme, ScopeType
from tools.recon.cert_transparency import cert_transparency
from tools.recon.dirfuzz import discover_paths
from tools.recon.dns_assets import dns_assets_from_dnsx
from tools.recon.dnsx import TakeoverCandidate, detect_takeover_candidates, resolve_records
from tools.recon.httpx import probe_endpoints
from tools.recon.ip_enrichment import compose_ip_enrichment
from tools.recon.llm import detect_llm_endpoints
from tools.recon.nmap import port_scan
from tools.recon.scope import filter_in_scope, host_of
from tools.recon.subfinder import enumerate_subdomains
from tools.recon.tls import check_dns_email_security, check_tls
from tools.recon.traceroute import run_traceroute
from tools.recon.waybackurls import historical_urls

logger = logging.getLogger(__name__)

# Subdomain prefixes that are high-value dirfuzz targets: more likely to expose
# admin interfaces, internal APIs, or sensitive paths than generic subdomains.
_DIRFUZZ_HIGH_VALUE_PREFIXES = frozenset(
    {
        "admin",
        "api",
        "app",
        "beta",
        "console",
        "dashboard",
        "dev",
        "internal",
        "manage",
        "portal",
        "staging",
        "test",
    }
)


def _dirfuzz_targets(endpoints: list[Endpoint], seed_domains: list[str]) -> list[Endpoint]:
    """Sort endpoints for dirfuzz priority: root domains first, high-value subdomains second."""
    seed_set = set(seed_domains)

    def _priority(ep: Endpoint) -> int:
        hostname = urlparse(ep.url).hostname or ""
        if hostname in seed_set:
            return 0
        if hostname.split(".")[0].lower() in _DIRFUZZ_HIGH_VALUE_PREFIXES:
            return 1
        return 2

    return sorted(endpoints, key=_priority)


# Third-party code hosting platforms that appear in H1 scope lists as URL-type
# assets pointing to repos/orgs, but whose infrastructure must never be enumerated.
_CODE_HOSTS: frozenset[str] = frozenset(
    {"github.com", "gitlab.com", "bitbucket.org", "sourceforge.net"}
)

# Asset types that represent live web targets worth enumerating with subfinder.
# H1 returns URL for bare domains (dash.cloudflare.com) and wildcards (*.teams.cloudflare.com).
_ACTIVE_RECON_TYPES: frozenset[ScopeType] = frozenset(
    {ScopeType.URL, ScopeType.WILDCARD, ScopeType.IP_ADDRESS}
)


__all__ = [
    "_ACTIVE_RECON_TYPES",
    "_CODE_HOSTS",
    "TakeoverCandidate",
    "cert_transparency",
    "check_dns_email_security",
    "check_tls",
    "compose_ip_enrichment",
    "detect_llm_endpoints",
    "detect_takeover_candidates",
    "discover_paths",
    "dns_assets_from_dnsx",
    "enumerate_subdomains",
    "filter_in_scope",
    "historical_urls",
    "host_of",
    "port_scan",
    "probe_endpoints",
    "resolve_records",
    "run_recon",
    "run_traceroute",
]


def run_recon(programme: Programme) -> AttackGraph:
    """Full recon pipeline for a single programme."""
    seed_domains: list[str] = []
    for item in programme.in_scope:
        if item.asset_type not in _ACTIVE_RECON_TYPES:
            continue
        parsed = urlparse(
            item.asset_identifier
            if "://" in item.asset_identifier
            else f"http://{item.asset_identifier}"
        )
        hostname = (parsed.hostname or "").lstrip("*.")
        if not hostname or (parsed.path or "").strip("/") or hostname in _CODE_HOSTS:
            continue
        seed_domains.append(hostname)
    seed_domains = list(dict.fromkeys(seed_domains))

    all_subdomains: list[str] = []
    for domain in seed_domains:
        all_subdomains.extend(enumerate_subdomains(domain))
    all_subdomains = list(dict.fromkeys(all_subdomains))

    in_scope_hosts = filter_in_scope(all_subdomains, programme)
    endpoints = probe_endpoints(in_scope_hosts)

    # Promote TLS SANs observed during probing to in-scope subdomains.
    # Multi-SAN certs leak every hostname the server is authoritative for;
    # the scope guard filters those that match the programme. Dormant
    # today because ``probe_endpoints`` is the TECH_DETECT shim (no
    # -tls-grab); activates the moment any caller flips run_recon to
    # HttpxMode.WEB_INVENTORY or an OA-side tool pipes WEB_INVENTORY
    # endpoints through this helper. Code lives upstream of the dormancy
    # so SANs join in_scope_hosts atomically with the probe that surfaced
    # them - downstream IP enrichment, traceroute, and DNS checks all see
    # the promoted hosts in one pass.
    san_candidates = list({san for ep in endpoints for san in ep.tls_sans})
    if san_candidates:
        promoted = filter_in_scope(san_candidates, programme)
        in_scope_hosts = list(dict.fromkeys(in_scope_hosts + promoted))

    # nmap scans hosts, not URLs - extract the hostname from each live
    # endpoint (``host_of`` returns "" for a hostless URL, which the
    # ``if host`` clause drops) so ``open_ports`` keys by FQDN, matching
    # the host-keyed lookups the ``Recon Open Ports`` slicer does downstream.
    live_hosts = [
        host
        for ep in endpoints
        if ep.status_code and ep.status_code < 500
        if (host := host_of(ep.url))
    ]
    open_ports = port_scan(live_hosts[:20])

    discovered = discover_paths(_dirfuzz_targets(endpoints, seed_domains))
    endpoints = endpoints + discovered

    all_tech: list[str] = []
    for ep in endpoints:
        all_tech.extend(ep.technologies)

    # Passive findings: TLS and DNS checks run here so all downstream agents
    # have this context without the Penetration Tester needing to repeat them.
    passive_findings = list(check_tls(endpoints))
    ep_hosts = [urlparse(ep.url).hostname or "" for ep in endpoints]
    all_domains = list(dict.fromkeys(ep_hosts + in_scope_hosts))
    passive_findings.extend(check_dns_email_security(all_domains))

    network_hops = run_traceroute(in_scope_hosts[:20])

    # IP-rooted enrichment: resolve A records once for the in-scope hosts,
    # unique-ify the IPs, compose the faithful IP subgraph (IPAddress /
    # Netblock / AutonomousSystem + registry / registrant assets + edges) via
    # Cymru + RDAP + dnsx PTR.
    dns_records = resolve_records(in_scope_hosts)
    unique_ips = list(dict.fromkeys(ip for record in dns_records for ip in record.a_records))
    ip_enrichment = compose_ip_enrichment(unique_ips)
    # The OAM subgraph of those same records: A / CNAME answers as
    # DNSRecordProperty entries hung off each host's FQDN node, plus the
    # BasicDNSRelation edges to the answer assets.
    dns_assets = dns_assets_from_dnsx(dns_records)

    return AttackGraph(
        programme=programme,
        subdomains=in_scope_hosts,
        endpoints=endpoints,
        open_ports=open_ports,
        technologies=list(dict.fromkeys(all_tech)),
        passive_findings=passive_findings,
        network_hops=network_hops,
        ip_enrichment=ip_enrichment,
        dns_records=dns_assets.records,
        relations=dns_assets.relations,
        # Cert aggregate for the sweep; per-host materialisation happens at
        # finalise (the bound handoff point), not here - run_recon stays
        # side-effect-free.
        tls_certificates=[ep.tls_certificate for ep in endpoints if ep.tls_certificate],
        notes=f"Seeded from {seed_domains}. {len(in_scope_hosts)} in-scope hosts.",
    )
