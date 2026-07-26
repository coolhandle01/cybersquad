"""OSINT Analyst - maps the in-scope attack surface.

The agent's tools split across sibling modules so each file owns one
cohesive responsibility:

- ``discovery`` - sweep + slicers + passive expansion (cert
  transparency, historical URLs, LLM endpoint detection) + active
  hostname probes + takeover detection. The "what is the surface"
  half. The two active-probe wrappers (``Discover Webpages``, ``Discover
  Takeover Candidates``) take ``list[FQDN]``; ``@cyber_tool``
  auto-detects the typed-target field and runs the programme scope
  guard in the wrapper rather than inline in the body. The shared
  ``current_programme`` reader lives in ``squad.tools.workspace_tools``.
- ``curation`` - lookup (CWE / OWASP) + ``Annotate Host`` +
  ``List Uncovered Hosts`` + ``Finalise Recon``. The "what do we record
  about the surface" half.

This module imports each wrapper, assembles ``MEMBER.tools``, and re-
exports both the wrappers and their args_schema classes so existing
consumers (tests, ``crew.py``, the contract tests in
``tests/squad/osint_analyst/test_args_schemas.py``) keep importing from
``squad.osint_analyst`` directly.
"""

from pathlib import Path

from squad import SquadMember, read_run_file_tool, read_run_filelist_tool
from squad.osint_analyst.tools.amass import (
    _AmassAddressesArgs,
    _AmassNetblocksArgs,
    _AmassSubdomainsArgs,
    amass_addresses_tool,
    amass_netblocks_tool,
    amass_subdomains_tool,
)
from squad.osint_analyst.tools.curation import (
    _AnnotateHostArgs,
    _FinaliseReconArgs,
    _ListUncoveredHostsArgs,
    _OsintLookupCweArgs,
    _OsintLookupOwaspArgs,
    annotate_host_tool,
    finalise_recon_tool,
    list_uncovered_hosts_tool,
    lookup_cwe_tool,
    lookup_owasp_tool,
)
from squad.osint_analyst.tools.discovery import (
    _DiscoverHistoricalUrlsArgs,
    _DiscoverLlmEndpointsArgs,
    _DiscoverSubdomainsArgs,
    _DiscoverTakeoverCandidatesArgs,
    _DiscoverWebpagesArgs,
    _ListEndpointsArgs,
    _ListOpenPortsArgs,
    _ListSubdomainsArgs,
    _RunInitialSweepArgs,
    discover_historical_urls_tool,
    discover_llm_endpoints_tool,
    discover_subdomains_tool,
    discover_takeover_candidates_tool,
    discover_webpages_tool,
    list_endpoints_tool,
    list_open_ports_tool,
    list_subdomains_tool,
    run_initial_sweep_tool,
)
from squad.osint_analyst.tools.enrichment import (
    _DiscoverHostServicesArgs,
    _LookupIpAssetsArgs,
    _LookupRdapAsnArgs,
    discover_host_services_tool,
    lookup_ip_assets_tool,
    lookup_rdap_asn_tool,
)
from squad.tools.workspace_tools import _ListRunFilesArgs, _ReadRunFileArgs

MEMBER = SquadMember(
    dir=Path(__file__).parent,
    tools=[
        run_initial_sweep_tool,
        list_subdomains_tool,
        list_endpoints_tool,
        list_open_ports_tool,
        discover_subdomains_tool,
        discover_historical_urls_tool,
        discover_llm_endpoints_tool,
        discover_webpages_tool,
        discover_takeover_candidates_tool,
        # Read what a prior Amass run already collected. No traffic.
        amass_subdomains_tool,
        amass_addresses_tool,
        amass_netblocks_tool,
        # Post-sweep pivot / enrichment
        lookup_ip_assets_tool,
        lookup_rdap_asn_tool,
        discover_host_services_tool,
        lookup_cwe_tool,
        lookup_owasp_tool,
        annotate_host_tool,
        list_uncovered_hosts_tool,
        finalise_recon_tool,
        # Shared workspace wrappers
        read_run_filelist_tool,
        read_run_file_tool,
    ],
    schemas={
        "Run Initial Sweep": _RunInitialSweepArgs,
        "List Subdomains": _ListSubdomainsArgs,
        "List Endpoints": _ListEndpointsArgs,
        "List Open Ports": _ListOpenPortsArgs,
        "Discover Subdomains": _DiscoverSubdomainsArgs,
        "Discover Historical URLs": _DiscoverHistoricalUrlsArgs,
        "Discover LLM Endpoints": _DiscoverLlmEndpointsArgs,
        "Discover Webpages": _DiscoverWebpagesArgs,
        "Discover Takeover Candidates": _DiscoverTakeoverCandidatesArgs,
        "Read Amass Subdomains": _AmassSubdomainsArgs,
        "Read Amass Addresses": _AmassAddressesArgs,
        "Read Amass Netblocks": _AmassNetblocksArgs,
        "Lookup IP Assets": _LookupIpAssetsArgs,
        "Lookup RDAP for ASN": _LookupRdapAsnArgs,
        "Discover Host Services": _DiscoverHostServicesArgs,
        "Lookup CWE": _OsintLookupCweArgs,
        "Lookup OWASP Guidance": _OsintLookupOwaspArgs,
        "Annotate Host": _AnnotateHostArgs,
        "List Uncovered Hosts": _ListUncoveredHostsArgs,
        "Finalise Recon": _FinaliseReconArgs,
        # Shared workspace wrappers (re-exported via squad.tools.workspace_tools)
        "List Run Files": _ListRunFilesArgs,
        "Read Run File": _ReadRunFileArgs,
    },
)

__all__ = [  # noqa: RUF022 - grouped by purpose, not alphabetised
    # Public API
    "MEMBER",
    # Wrappers - discovery
    "discover_historical_urls_tool",
    "discover_host_services_tool",
    "discover_llm_endpoints_tool",
    "discover_subdomains_tool",
    "discover_takeover_candidates_tool",
    "discover_webpages_tool",
    "list_endpoints_tool",
    "list_open_ports_tool",
    "list_subdomains_tool",
    "lookup_ip_assets_tool",
    "lookup_rdap_asn_tool",
    "run_initial_sweep_tool",
    # Wrappers - Amass asset database (read-only, no traffic)
    "amass_addresses_tool",
    "amass_netblocks_tool",
    "amass_subdomains_tool",
    # Wrappers - curation
    "annotate_host_tool",
    "finalise_recon_tool",
    "list_uncovered_hosts_tool",
    "lookup_cwe_tool",
    "lookup_owasp_tool",
    # args_schema classes (re-exported so test imports stay stable)
    "_AmassAddressesArgs",
    "_AmassNetblocksArgs",
    "_AmassSubdomainsArgs",
    "_AnnotateHostArgs",
    "_DiscoverHistoricalUrlsArgs",
    "_DiscoverHostServicesArgs",
    "_DiscoverLlmEndpointsArgs",
    "_DiscoverSubdomainsArgs",
    "_DiscoverTakeoverCandidatesArgs",
    "_DiscoverWebpagesArgs",
    "_FinaliseReconArgs",
    "_ListEndpointsArgs",
    "_ListOpenPortsArgs",
    "_ListSubdomainsArgs",
    "_ListUncoveredHostsArgs",
    "_LookupIpAssetsArgs",
    "_LookupRdapAsnArgs",
    "_OsintLookupCweArgs",
    "_OsintLookupOwaspArgs",
    "_RunInitialSweepArgs",
]
