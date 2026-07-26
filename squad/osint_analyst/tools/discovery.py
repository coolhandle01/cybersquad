"""
squad/osint_analyst/tools/discovery.py - the OSINT discovery surface.

Tools the OA uses to map the in-scope attack surface: kick off the
initial sweep, slice over the in-progress sweep (subdomains /
endpoints / open ports), expand discovery via passive sources (cert
transparency, historical URL archive), spot LLM-bearing endpoints,
and follow up with active probes against newly-surfaced hostnames.
"""

from pydantic import BaseModel, Field, TypeAdapter, ValidationError

import runtime
from models import (
    FQDN,
    Endpoint,
    EndpointPage,
    HttpUrl,
    LlmEndpoint,
    OpenPortsMap,
    TakeoverCandidate,
)
from squad import cyber_tool
from squad.tools.workspace_tools import current_programme
from tools.recon import (
    cert_transparency,
    detect_llm_endpoints,
    detect_takeover_candidates,
    historical_urls,
    run_recon,
)
from tools.recon import probe_endpoints as probe_endpoints_impl
from tools.recon.query import recon_endpoints, recon_open_ports, recon_subdomains
from tools.recon.scope import (
    TargetEndpoints,
    TargetFQDN,
    TargetFQDNs,
)

# A bare ``FQDN(x)`` / ``HttpUrl(x)`` call does NOT run the AfterValidator -
# the typed-string aliases only validate + normalise through Pydantic. These
# adapters are the coercion point for the tool-captured strings the recon
# binaries return, so the typed return shapes are real, not cosmetic. The
# single-value ``HttpUrl`` adapter is used per-entry so one malformed archive
# URL can be dropped without failing the batch.
_FQDN_LIST_ADAPTER: TypeAdapter[list[FQDN]] = TypeAdapter(list[FQDN])
_HTTP_URL_ADAPTER: TypeAdapter[HttpUrl] = TypeAdapter(HttpUrl)


class _RunInitialSweepArgs(BaseModel):
    """Explicit args_schema for the Run Initial Sweep tool.

    Takes no parameters - the programme is sourced from the workspace
    (``<run_dir>/programme.json``, written by the Programme Manager's
    ``Save Selected Programme`` at run start). The empty schema is
    still declared so the closed-world contract test in the OSINT
    Analyst's ``test_args_schemas.py`` accounts for the tool.
    """


@cyber_tool("Run Initial Sweep", args_schema=_RunInitialSweepArgs)
def run_initial_sweep_tool() -> str:
    """
    Run the initial OSINT sweep against the selected programme's in-scope
    assets: subfinder for subdomain enumeration, httpx for live HTTP/S
    probing and tech detection, nmap for port scanning, ffuf for content
    discovery, plus passive TLS and DNS email-security checks. Writes the
    serialised inventory to ``attack_graph.json`` (the OA's internal draft) in the
    run directory and returns the relative filename.

    This is the inventory step. Annotate the interesting hosts with
    Annotate Host and call Finalise Recon to produce the canonical
    ``recon.json`` that the Vulnerability Researcher and Penetration
    Tester consume.
    """
    programme = current_programme()
    result = run_recon(programme)
    out_path = runtime.run_dir() / "attack_graph.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(result.model_dump_json(), encoding="utf-8")
    return "attack_graph.json"


class _ListSubdomainsArgs(BaseModel):
    """Explicit args_schema for the OSINT List Subdomains tool."""

    attack_graph_path: str = Field(
        default="attack_graph.json",
        description=(
            "Relative path to the OA's in-progress sweep file. Defaults to"
            " ``attack_graph.json`` (the canonical name written by Run Initial"
            " Sweep). Override only when re-inspecting a sweep written"
            " under a different name."
        ),
    )
    host_filter: str | None = Field(
        default=None,
        description=(
            "Case-insensitive substring match against each subdomain"
            " (e.g. 'api' returns every subdomain containing 'api',"
            " regardless of position). Omit or pass null to get the full"
            " list. Useful for scoping a per-role annotation pass."
        ),
    )


@cyber_tool("List Subdomains", args_schema=_ListSubdomainsArgs)
def list_subdomains_tool(
    attack_graph_path: str = "attack_graph.json", host_filter: str | None = None
) -> list[FQDN]:
    """
    Return the in-scope subdomains in the OA's draft sweep. ``host_filter`` is
    a case-insensitive substring (e.g. "api" returns every subdomain
    containing "api"). Use this to inspect the sweep before deciding which
    hosts to annotate. Each returned hostname is ready to pass straight
    into ``Annotate Host``, ``Discover Webpages``, or ``Discover Takeover
    Candidates`` - no further normalisation needed.
    """
    return [FQDN(h) for h in recon_subdomains(attack_graph_path, host_filter=host_filter)]


class _ListEndpointsArgs(BaseModel):
    """Explicit args_schema for the OSINT List Endpoints tool."""

    attack_graph_path: str = Field(
        default="attack_graph.json",
        description="Relative path to the OA's sweep file. Defaults to ``attack_graph.json``.",
    )
    status: int | None = Field(
        default=None,
        description=(
            "Exact HTTP status code to filter by (e.g. 200 for live, 401 /"
            " 403 for auth-shaped, 301 / 302 for redirectors). Omit or pass"
            " null for any status."
        ),
    )
    tech: str | None = Field(
        default=None,
        description=(
            "Case-insensitive substring match against each endpoint's"
            " technologies list (e.g. 'wordpress' matches 'WordPress 6.4')."
            " Use when scoping a per-stack annotation pass."
        ),
    )
    host_contains: str | None = Field(
        default=None,
        description=(
            "Case-insensitive substring match against the endpoint URL. Use"
            " to narrow to a hostname or path family."
        ),
    )
    offset: int = Field(
        default=0,
        description=(
            "Zero-based row offset for paging. Use with ``limit`` to walk large result sets."
        ),
    )
    limit: int = Field(
        default=50,
        description=(
            "Maximum number of endpoints to return in this page. The OA's"
            " context budget rewards small pages; default 50 is usually"
            " right - go larger only when the conjunctive filters above"
            " already narrowed the result heavily."
        ),
    )


@cyber_tool("List Endpoints", args_schema=_ListEndpointsArgs)
def list_endpoints_tool(
    attack_graph_path: str = "attack_graph.json",
    status: int | None = None,
    tech: str | None = None,
    host_contains: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> EndpointPage:
    """
    Return a paginated slice of endpoints from the sweep matching the given
    filters (conjunctive). ``tech`` matches case-insensitively as a
    substring against each endpoint's technologies; ``host_contains``
    matches the URL. Use this to find which hostnames run a given stack
    before annotating.
    """
    return recon_endpoints(
        attack_graph_path,
        status=status,
        tech=tech,
        host_contains=host_contains,
        offset=offset,
        limit=limit,
    )


class _ListOpenPortsArgs(BaseModel):
    """Explicit args_schema for the OSINT List Open Ports tool."""

    attack_graph_path: str = Field(
        default="attack_graph.json",
        description="Relative path to the OA's sweep file. Defaults to ``attack_graph.json``.",
    )
    host: FQDN | None = Field(
        default=None,
        description=(
            "Exact hostname to restrict the result to (no wildcards, no"
            " substring). Validated as an RFC 1123 hostname - URLs / ports"
            " / paths reject upstream. Omit or pass null to get the full"
            " per-host port map."
        ),
    )


@cyber_tool("List Open Ports", args_schema=_ListOpenPortsArgs)
def list_open_ports_tool(
    attack_graph_path: str = "attack_graph.json", host: FQDN | None = None
) -> OpenPortsMap:
    """
    Return the open-port map per host from the sweep. Passing a ``host``
    restricts the result to that single host. Use to surface non-HTTP
    services (Redis 6379, Elasticsearch 9200, Mongo 27017, etc.) that an
    annotation should call out.
    """
    return OpenPortsMap(hosts=recon_open_ports(attack_graph_path, host=host))


class _DiscoverSubdomainsArgs(BaseModel):
    """Explicit args_schema for the Discover Subdomains tool."""

    domain: TargetFQDN = Field(
        description=(
            "Apex domain to look up in crt.sh certificate transparency logs"
            " (e.g. 'example.com'). Validated as an RFC 1123 hostname"
            " (URLs / ports / paths reject upstream). Pass an apex, not a"
            " subdomain - crt.sh returns the broader set when queried on"
            " the apex."
        ),
    )


@cyber_tool("Discover Subdomains", args_schema=_DiscoverSubdomainsArgs)
def discover_subdomains_tool(domain: FQDN) -> list[FQDN]:
    """
    Query crt.sh certificate transparency logs to discover subdomains not
    found by active enumeration. Returns deduplicated hostnames as typed
    FQDNs. Feed newly discovered hosts to Discover Webpages to determine
    which are live.
    """
    return _FQDN_LIST_ADAPTER.validate_python(cert_transparency(domain))


class _DiscoverHistoricalUrlsArgs(BaseModel):
    """Explicit args_schema for the Discover Historical URLs tool."""

    domain: TargetFQDN = Field(
        description=(
            "Domain to query waybackurls for (apex or subdomain). Validated"
            " as an RFC 1123 hostname (URLs / ports / paths reject"
            " upstream). Returns historical URLs the Wayback Machine has"
            " archived. Many paths will be 404s today; feed candidates to"
            " Discover Webpages to confirm liveness before annotating."
        ),
    )


@cyber_tool("Discover Historical URLs", args_schema=_DiscoverHistoricalUrlsArgs)
def discover_historical_urls_tool(domain: FQDN) -> list[HttpUrl]:
    """
    Use waybackurls to find historical endpoints for a domain from the
    Wayback Machine. Surfaces paths that may no longer be linked but still
    exist - candidates for Discover Webpages.

    Returns typed URL strings, not ``Endpoint`` objects: these are archive
    entries, *unprobed*, so we have no status code or liveness to put on an
    ``Endpoint`` yet. Malformed archive entries (no scheme / host) are
    dropped rather than failing the batch. Feed the survivors to Discover
    Webpages to confirm which are live.
    """
    urls: list[HttpUrl] = []
    for raw in historical_urls(domain):
        try:
            urls.append(_HTTP_URL_ADAPTER.validate_python(raw))
        except ValidationError:
            continue
    return urls


class _DiscoverLlmEndpointsArgs(BaseModel):
    """Explicit args_schema for the Discover LLM Endpoints tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Live endpoint objects from the sweep (or a filtered subset)."
            " Each entry needs ``url`` and ideally ``technologies``;"
            " ``status_code`` is honoured if present. Pass the typed list"
            " straight through from List Endpoints - do not stringify."
        ),
    )


@cyber_tool("Discover LLM Endpoints", args_schema=_DiscoverLlmEndpointsArgs)
def discover_llm_endpoints_tool(endpoints: list[Endpoint]) -> list[LlmEndpoint]:
    """
    Scan a set of live endpoints for signals that they are backed by an LLM
    or AI assistant (URL path heuristics, OpenAI-format response keys,
    EventSource content-type, self-identification phrases). Pass the
    sweep's endpoint list (or a filtered subset) straight through from
    List Endpoints. Returned hits deserve a HIGH-priority annotation and
    a note pointing the Penetration Tester at prompt-injection probes.
    """
    # CrewAI's args_schema validation produces list[dict] from the LLM JSON
    # before invoking us; re-validate so we always see ``Endpoint`` instances
    # regardless of whether the caller is the runtime or a direct test invocation.
    parsed = [Endpoint.model_validate(e) for e in endpoints]
    return [LlmEndpoint.model_validate(ep.model_dump()) for ep in detect_llm_endpoints(parsed)]


class _DiscoverWebpagesArgs(BaseModel):
    """Explicit args_schema for the Discover Webpages tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs to re-probe with httpx for liveness, status code,"
            " and technology fingerprinting. Each entry is validated as an"
            " RFC 1123 hostname; URLs / ports / paths reject upstream"
            " (catches the common 'agent handed us a URL when we asked for"
            " a hostname' case before the scope filter silently drops it)."
            " Typically the net-new ones surfaced by Discover"
            " Subdomains or Discover Historical URLs that were missed by"
            " the initial sweep. The wrapper's scope filter drops any"
            " hostname outside the selected programme's structured scope"
            " before HTTP traffic fires."
        ),
    )


@cyber_tool("Discover Webpages", args_schema=_DiscoverWebpagesArgs)
def discover_webpages_tool(hostnames: list[FQDN]) -> list[Endpoint]:
    """
    Re-probe a list of hostnames with httpx to confirm liveness, capture
    status codes, and fingerprint technologies. Use this on hostnames
    surfaced by Discover Subdomains or Discover Historical URLs that
    were not in the initial sweep.

    The wrapper scope-filters the hostnames against the selected
    programme's structured scope before this body runs; out-of-scope
    hostnames are dropped silently (we never probe outside scope, even
    for fingerprinting). Returns a list of Endpoint with {url,
    status_code, technologies, parameters}. Net-new endpoints can then
    be annotated with Annotate Host.
    """
    if not hostnames:
        return []
    return list(probe_endpoints_impl(hostnames))


class _DiscoverTakeoverCandidatesArgs(BaseModel):
    """Explicit args_schema for the Discover Takeover Candidates tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs to resolve via dnsx and flag for subdomain takeover."
            " Each entry is validated as an RFC 1123 hostname; URLs / ports"
            " / paths reject upstream. A candidate fires when the CNAME"
            " points to a known-vulnerable provider (AWS S3, Heroku,"
            " GitHub Pages, Azure, Vercel, Netlify, ...) or when the CNAME"
            " chain dangles. The wrapper's scope filter drops any hostname"
            " outside the selected programme's structured scope before any"
            " DNS traffic fires."
        ),
    )


@cyber_tool("Discover Takeover Candidates", args_schema=_DiscoverTakeoverCandidatesArgs)
def discover_takeover_candidates_tool(
    hostnames: list[FQDN],
) -> list[TakeoverCandidate]:
    """
    Resolve each hostname via dnsx and flag subdomain-takeover candidates.

    A candidate is flagged when the host's CNAME points to a known-vulnerable
    provider (AWS S3, Heroku, GitHub Pages, Azure, Vercel, Netlify, ...) or
    when the CNAME chain dangles (CNAME exists but resolves to no A records).
    Returns a list of TakeoverCandidate where ``reason`` is one of
    ``cname_to_vulnerable_provider`` or ``dangling_cname``.

    Each candidate is exactly that - a candidate. Follow up by annotating
    the host HIGH priority with a note pointing the Penetration Tester at
    the service-specific confirmation step (probe the host and check for
    the "no such bucket" / "no such app" / "there isn't a GitHub Pages
    site here" body fingerprint).

    The wrapper scope-filters the hostnames against the selected
    programme's structured scope before this body runs.
    """
    if not hostnames:
        return []
    return list(detect_takeover_candidates(hostnames))
