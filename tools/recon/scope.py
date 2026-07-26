"""Scope filtering for recon results, exposed as Pydantic typed aliases.

The agent-facing surface is four ``Annotated`` types - the LLM picks
targets, and these are the field types that constrain what survives
``args_schema.model_validate(...)``:

- ``TargetFQDNs`` - ``list[FQDN]`` that silently drops any
  hostname outside the in-flight programme's scope. Mixed-input
  semantics: the LLM may pass a wider candidate list and only the
  in-scope subset reaches the wrapper body.
- ``TargetEndpoints`` - ``list[Endpoint]`` with the same filter
  semantics, host-extracted from ``Endpoint.url`` via stdlib
  ``urllib.parse.urlparse``.
- ``TargetFQDN`` / ``TargetEndpoint`` - single-target variants
  that raise ``ValueError`` on an out-of-scope pick rather than
  silently dropping it. A single target is the LLM committing to one
  address, and a loud reject surfaces the mismatch instead of the run
  going quiet.

Pydantic's ``AfterValidator`` runs as part of every
``args_schema.model_validate(...)`` pass CrewAI does, so the scope guard
is built into the type the LLM sees - no per-tool decorator parameter,
no per-tool body dance. The validator reads ``current_programme()``
(the run-dir Programme snapshot the PM writes at run start); a tool
called without a programme bound raises ``FileNotFoundError`` loudly
rather than running unscoped.

Lower-level helpers (``filter_in_scope`` over a host list,
``host_of`` over a URL string) stay exposed for callers outside the
agent path (the OSINT sweep filters its own discoveries pre-recon).
"""

from __future__ import annotations

import logging
from typing import Annotated
from urllib.parse import urlparse

from pydantic import AfterValidator

from models import FQDN, Endpoint
from models.h1 import Programme, ScopeType

logger = logging.getLogger(__name__)


def host_of(url: str) -> str:
    """Extract the hostname component from an HTTP/S URL.

    Thin stdlib wrapper - kept as a named helper so call sites read
    naturally and there is one place to change should ``urlparse``'s
    behaviour ever need supplementing. Returns ``""`` for a URL with no
    host, matching ``urlparse``'s own contract.
    """
    return urlparse(url).hostname or ""


def filter_in_scope(hosts: list[str], programme: Programme) -> list[str]:
    """Return only hosts that fall within the programme's in-scope assets.

    Uses exact-match or dot-boundary check to prevent subdomain
    confusion attacks (``evil.notexample.com`` must not match
    ``example.com``). Non-URL / non-WILDCARD scope items (IP_ADDRESS,
    CIDR, OTHER - mobile app IDs) are skipped; they do not match
    hostnames.
    """
    allowed: list[str] = []
    for host in hosts:
        for scope_item in programme.in_scope:
            if scope_item.asset_type not in (ScopeType.URL, ScopeType.WILDCARD):
                continue
            pattern = scope_item.asset_identifier.lstrip("*.")
            if host == pattern or host.endswith("." + pattern):
                allowed.append(host)
                break
    logger.info(
        "Scope filter: %d/%d hosts in scope for %s",
        len(allowed),
        len(hosts),
        programme.handle,
    )
    return allowed


def _filter_fqdns(hosts: list[str]) -> list[str]:
    """Pydantic ``AfterValidator`` for ``list[FQDN]`` fields.

    Sources the in-flight Programme via ``current_programme()`` and
    returns the in-scope subset. Lazy-imported to break the
    ``squad.tools.workspace_tools`` -> ``squad`` cycle that would otherwise
    fire at module load.
    """
    if not hosts:
        return hosts
    from squad.tools.workspace_tools import current_programme

    return filter_in_scope(hosts, current_programme())


def _filter_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Pydantic ``AfterValidator`` for ``list[Endpoint]`` fields.

    Same scope source as ``_filter_fqdns``; extracts each
    endpoint's host via stdlib ``urlparse`` and keeps only the
    endpoints whose host survives the filter. Pydantic has already
    validated each item as an ``Endpoint`` by the time this runs - the
    input is always typed instances, never the dict shape CrewAI hands
    over later.
    """
    if not endpoints:
        return endpoints
    from squad.tools.workspace_tools import current_programme

    programme = current_programme()
    in_scope = set(filter_in_scope([host_of(ep.url) for ep in endpoints], programme))
    return [ep for ep in endpoints if host_of(ep.url) in in_scope]


def _require_fqdn_in_scope(host: str) -> str:
    """Pydantic ``AfterValidator`` for single ``FQDN`` fields.

    A single hostname is the agent committing to one target; an
    out-of-scope value is a loud error, not silent drop. Raises
    ``ValueError`` if the hostname is not in scope.
    """
    from squad.tools.workspace_tools import current_programme

    if not filter_in_scope([host], current_programme()):
        raise ValueError(f"hostname {host!r} is not in the selected programme's scope")
    return host


def _require_endpoint_in_scope(endpoint: Endpoint) -> Endpoint:
    """Pydantic ``AfterValidator`` for single ``Endpoint`` fields.

    Mirror of ``_require_fqdn_in_scope`` but pulls the host out of
    ``endpoint.url`` first. Raises ``ValueError`` if the host is OOS.
    """
    from squad.tools.workspace_tools import current_programme

    host = host_of(endpoint.url)
    if not filter_in_scope([host], current_programme()):
        raise ValueError(f"endpoint host {host!r} is not in the selected programme's scope")
    return endpoint


# Public agent-facing typed aliases. The LLM picks targets; Pydantic's
# args_schema validation drops out-of-scope picks (lists) or rejects
# them (singles) before any wrapper body runs. The cybersquad-tool
# skill carries the picking guidance.
TargetFQDNs = Annotated[list[FQDN], AfterValidator(_filter_fqdns)]
TargetEndpoints = Annotated[list[Endpoint], AfterValidator(_filter_endpoints)]
TargetFQDN = Annotated[FQDN, AfterValidator(_require_fqdn_in_scope)]
TargetEndpoint = Annotated[Endpoint, AfterValidator(_require_endpoint_in_scope)]
