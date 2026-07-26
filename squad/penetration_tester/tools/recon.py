"""
squad/penetration_tester/tools/recon.py - typed slicers over the OSINT
Analyst's ``recon.json``.

The PT does not run recon itself - the OA produced ``recon.json`` -
but it needs narrow views (subdomain list, filtered endpoint page,
per-host port map) to choose which probes to run without loading the
whole AttackGraph. These three @cyber_tool wrappers are those typed
slicers. They are read-only, idempotent, and write nothing to the
workspace.
"""

from pydantic import BaseModel, Field

from models import FQDN, EndpointPage, OpenPortsMap
from squad import cyber_tool
from tools.recon.query import recon_endpoints, recon_open_ports, recon_subdomains


class _PtReconSubdomainsArgs(BaseModel):
    """Explicit args_schema for the PT's Recon Subdomains tool."""

    recon_path: str = Field(
        description=(
            "Relative path to the OSINT Analyst's ``recon.json`` in the"
            " current run directory (the typed artefact ``Finalise"
            " Recon`` wrote). The slicer reads the ``subdomains`` field"
            " - in-scope hostnames the OA surfaced via subfinder, cert"
            " transparency, and historical-URL discovery. Pass"
            " ``recon.json`` (the canonical filename) unless a"
            " non-default writer produced it."
        ),
    )
    host_filter: str | None = Field(
        default=None,
        description=(
            "Optional case-insensitive substring filter on the returned"
            " subdomains. Passing ``api`` returns every subdomain"
            " containing ``api``; omit (None) for the full list."
            " Substring (not glob) - the wrapper does not interpret"
            " ``*`` or shell-style patterns."
        ),
    )


@cyber_tool("Recon Subdomains", args_schema=_PtReconSubdomainsArgs)
def recon_subdomains_tool(recon_path: str, host_filter: str | None = None) -> list[FQDN]:
    """
    Return the in-scope subdomains discovered during recon. Pass the recon.json
    path you received from the OSINT Analyst. ``host_filter`` is a
    case-insensitive substring (e.g. "api" returns every subdomain containing
    "api"). Use this instead of reading recon.json directly when you only need
    the subdomain list. Each returned hostname is ready to drop into the
    port-specific probes (``Recon Open Ports``, ``Unauthenticated
    Elasticsearch Check``, etc.) without further normalisation.
    """
    return [FQDN(h) for h in recon_subdomains(recon_path, host_filter=host_filter)]


class _PtReconEndpointsArgs(BaseModel):
    """Explicit args_schema for the PT's Recon Endpoints tool."""

    recon_path: str = Field(
        description=(
            "Relative path to the OSINT Analyst's ``recon.json`` in the"
            " current run directory (the typed artefact ``Finalise"
            " Recon`` wrote). The slicer reads the ``endpoints`` field"
            " - the per-URL records httpx / ffuf / LLM-endpoint"
            " detection produced - and applies the filters below"
            " server-side before returning an ``EndpointPage``."
        ),
    )
    status: int | None = Field(
        default=None,
        description=(
            "Conjunctive HTTP status filter (e.g. ``200`` returns only"
            " endpoints that responded 200 during the sweep). Omit"
            " (None) to skip the filter."
        ),
    )
    # FIXME #83 this should be a list of Frameworks
    tech: str | None = Field(
        default=None,
        description=(
            "Conjunctive case-insensitive tech filter against the"
            " endpoint's detected ``technologies`` list (e.g."
            " ``wordpress`` returns only WordPress endpoints). Pair"
            " with ``status`` to narrow further."
        ),
    )
    host_contains: str | None = Field(
        default=None,
        description=(
            "Conjunctive case-insensitive substring filter on the"
            " endpoint URL. Use to scope to a host segment (``admin``"
            " returns every endpoint whose URL contains ``admin``)."
        ),
    )
    offset: int = Field(
        default=0,
        description=(
            "Pagination offset into the filtered endpoint list. Combined"
            " with ``limit`` to walk the surface in pages - re-call"
            " with a larger offset to paginate through."
        ),
    )
    limit: int = Field(
        default=50,
        description=(
            "Page size for the pagination cursor (default 50). The"
            " returned ``EndpointPage`` carries ``total`` / ``offset``"
            " / ``returned`` so you can tell whether more remain."
        ),
    )


@cyber_tool("Recon Endpoints", args_schema=_PtReconEndpointsArgs)
# Every filter is a named parameter so the LLM can pick the slice it wants;
# collapsing into a payload dict would force the agent to guess valid keys.
# pylint: disable=R0913,R0917
def recon_endpoints_tool(
    recon_path: str,
    status: int | None = None,
    tech: str | None = None,
    host_contains: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> EndpointPage:
    """
    Query the endpoints discovered during recon without loading the whole
    AttackGraph. Filters are conjunctive: ``status=200`` and ``tech="wordpress"``
    returns endpoints satisfying both. ``host_contains`` matches the URL
    case-insensitively. Returns an EndpointPage with total, offset, returned,
    and a typed endpoints list - paginate by re-calling with a larger offset.

    Use this to build the ``endpoints`` argument for the narrow probe tools
    (sqlmap_tool, nuclei_scan_tool, etc.): pass ``page.endpoints`` straight
    through - the probe wrappers accept ``list[Endpoint]`` directly.
    """
    return recon_endpoints(
        recon_path,
        status=status,
        tech=tech,
        host_contains=host_contains,
        offset=offset,
        limit=limit,
    )


class _PtReconOpenPortsArgs(BaseModel):
    """Explicit args_schema for the PT's Recon Open Ports tool."""

    recon_path: str = Field(
        description=(
            "Relative path to the OSINT Analyst's ``recon.json`` in the"
            " current run directory (the typed artefact ``Finalise"
            " Recon`` wrote). The slicer reads the ``open_ports`` field"
            " - the per-host port map nmap produced - and returns it"
            " filtered to a single host or in full."
        ),
    )
    host: FQDN | None = Field(
        default=None,
        description=(
            "Optional bare hostname to restrict the open-port map to a"
            " single target - no scheme, no port suffix, no path. Useful"
            " when deciding which port-specific probe to run against one"
            " host (Elasticsearch on 9200, Redis on 6379, MongoDB on"
            " 27017, etc.). Omit (None) to return the per-host map for"
            " every scanned host."
        ),
    )


@cyber_tool("Recon Open Ports", args_schema=_PtReconOpenPortsArgs)
def recon_open_ports_tool(recon_path: str, host: str | None = None) -> OpenPortsMap:
    """
    Return the open-port map per host from recon.json. Passing a ``host``
    restricts the result to that single host. Use this to decide which of the
    port-specific probes to run (Elasticsearch on 9200, Redis on 6379, etc.)
    without loading the whole AttackGraph.
    """
    return OpenPortsMap(hosts=recon_open_ports(recon_path, host=host))
