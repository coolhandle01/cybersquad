"""
tools/recon/query.py - slice a saved AttackGraph without loading it whole.

The Penetration Tester gets a recon.json path from the OSINT Analyst.
Reading the entire file inflates its context with material it does not
need for the next probe (e.g. a 4MB Cloudflare subdomain dump when the
agent only wants to know which endpoints serve WordPress).

Each function reads recon.json, filters, and returns a focused slice -
so the agent can issue a typed query rather than a brute-force read.
"""

from __future__ import annotations

from models import AttackGraph, EndpointPage
from tools.workspace import resolve_run_path


def _load(recon_path: str) -> AttackGraph:
    return AttackGraph.model_validate_json(resolve_run_path(recon_path).read_text(encoding="utf-8"))


def recon_subdomains(recon_path: str, host_filter: str | None = None) -> list[str]:
    """Return the in-scope subdomains discovered for this run.

    ``host_filter`` is a case-insensitive substring match (e.g. "api" returns
    every subdomain containing "api"). None returns all subdomains.
    """
    subs = _load(recon_path).subdomains
    if host_filter is None:
        return subs
    needle = host_filter.lower()
    return [s for s in subs if needle in s.lower()]


def recon_endpoints(
    recon_path: str,
    status: int | None = None,
    tech: str | None = None,
    host_contains: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> EndpointPage:
    """Return a paginated slice of endpoints matching the given filters.

    Filters are conjunctive: a status of 200 *and* tech "wordpress" returns
    only endpoints satisfying both. ``tech`` matches case-insensitively as a
    substring against each endpoint's technologies. ``host_contains`` matches
    case-insensitively against the URL.

    Returns a dict with the total matching count, the offset/returned counts
    for this page, and the endpoint dicts. Paginate by re-calling with
    increasing ``offset`` until ``offset + returned >= total``.
    """
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if limit < 1:
        raise ValueError("limit must be at least 1")
    endpoints = _load(recon_path).endpoints
    if status is not None:
        endpoints = [e for e in endpoints if e.status_code == status]
    if tech is not None:
        needle = tech.lower()
        endpoints = [e for e in endpoints if any(needle in t.lower() for t in e.technologies)]
    if host_contains is not None:
        needle = host_contains.lower()
        endpoints = [e for e in endpoints if needle in e.url.lower()]
    total = len(endpoints)
    page = endpoints[offset : offset + limit]
    return EndpointPage(total=total, offset=offset, returned=len(page), endpoints=page)


def recon_open_ports(recon_path: str, host: str | None = None) -> dict[str, list[int]]:
    """Return the open-port map per host.

    Passing a ``host`` returns just that host's ports (empty dict if the
    host has no entry). None returns the full map.
    """
    ports = _load(recon_path).open_ports
    if host is None:
        return dict(ports)
    return {host: ports[host]} if host in ports else {}
