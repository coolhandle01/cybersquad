"""
squad/osint_analyst/tools/amass.py - reading the OWASP Amass asset database.

Amass is a producer with no consumer story: since v5 it writes its results
into a SQLite asset database and leaves the text output empty, so a pipeline
built on ``-o subs.txt`` succeeds having found nothing. These tools are the
read side, via ``oamx``.

They send no traffic. Everything here reports what Amass already collected,
which is the property that makes the surface safe to hand to an agent -
unlike the active tools in ``discovery.py``, calling one of these cannot
touch a target.
"""

from pydantic import BaseModel, Field

from models import FQDN, IPAddress, Netblock
from squad import cyber_tool
from tools.recon.amass import (
    AmassFilters,
    amass_addresses,
    amass_netblocks,
    amass_subdomains,
)
from tools.recon.scope import TargetFQDNs


class _AmassSubdomainsArgs(BaseModel):
    """Explicit args_schema for the Read Amass Subdomains tool."""

    domains: TargetFQDNs = Field(
        description=(
            "Root domains to scope the read to, e.g. ``example.com``."
            " Out-of-scope entries are dropped before the database is"
            " touched. Subdomains are matched by suffix, so one root"
            " domain returns the whole tree beneath it."
        ),
    )
    resolved_only: bool = Field(
        default=False,
        description=(
            "Drop hostnames with no DNS record. Set this when the output"
            " feeds an active probe - unresolved names cost a scan slot"
            " and answer nothing. Leave false when inventorying the full"
            " known surface, including names that once resolved."
        ),
    )
    since: str | None = Field(
        default=None,
        description=(
            "Only assets seen within this window, e.g. ``24h``, ``7d``,"
            " ``2w``. Use to narrow a large database to recent activity."
        ),
    )
    new_only: bool = Field(
        default=False,
        description=(
            "With ``since``, return only hostnames *first* seen in that"
            " window. A host known for a month that a second source just"
            " re-confirmed is not new and will not appear. Use when"
            " looking for genuine change rather than re-confirmation."
        ),
    )
    min_confidence: int = Field(
        default=0,
        ge=0,
        le=100,
        description=(
            "Drop assets below this source confidence. Raise it to shed"
            " brute-force guesses (typically 50) and keep names a data"
            " source actually observed (typically 95-100)."
        ),
    )


@cyber_tool("Read Amass Subdomains", args_schema=_AmassSubdomainsArgs)
def amass_subdomains_tool(
    domains: list[FQDN],
    resolved_only: bool = False,
    since: str | None = None,
    new_only: bool = False,
    min_confidence: int = 0,
) -> list[FQDN]:
    """
    Read hostnames OWASP Amass has already discovered, from its asset
    database. Sends no traffic and cannot start a scan - this only reports
    what a previous Amass run collected.

    Returns nothing if Amass has not been run against these domains, or if
    its database is elsewhere. That is a real answer, not an error: an empty
    result means the database holds nothing matching, and the fix is to run
    Amass rather than to retry this tool.

    Complements Discover Subdomains (certificate transparency): Amass draws
    on many sources at once and carries per-name provenance, so use this
    first where a database exists and fall back to the narrower passive
    sources where it does not.
    """
    if not domains:
        return []
    return amass_subdomains(
        [str(domain) for domain in domains],
        AmassFilters(
            since=since,
            new_only=new_only,
            resolved_only=resolved_only,
            min_confidence=min_confidence,
        ),
    )


class _AmassAddressesArgs(BaseModel):
    """Explicit args_schema for the Read Amass Addresses tool."""

    domains: TargetFQDNs = Field(
        description=(
            "Root domains to scope the read to. Addresses are reached by"
            " walking the graph out from in-scope hostnames, so a shared"
            " CDN's other customers are not pulled in with them."
        ),
    )
    since: str | None = Field(
        default=None,
        description="Only addresses seen within this window, e.g. ``24h``, ``7d``.",
    )
    min_confidence: int = Field(
        default=0,
        ge=0,
        le=100,
        description=(
            "Drop addresses below this source confidence (0-100). Raise it"
            " when the inventory will drive active scanning."
        ),
    )


@cyber_tool("Read Amass Addresses", args_schema=_AmassAddressesArgs)
def amass_addresses_tool(
    domains: list[FQDN],
    since: str | None = None,
    min_confidence: int = 0,
) -> list[IPAddress]:
    """
    Read the IP addresses OWASP Amass associated with these domains, each
    carrying the sources that asserted it and how confident they were. Sends
    no traffic.

    Prefer this over re-resolving hostnames when a database exists: it
    reflects everything Amass saw across all its sources, including addresses
    a single DNS answer would miss.
    """
    if not domains:
        return []
    return amass_addresses(
        [str(domain) for domain in domains],
        AmassFilters(since=since, min_confidence=min_confidence),
    )


class _AmassNetblocksArgs(BaseModel):
    """Explicit args_schema for the Read Amass Netblocks tool."""

    domains: TargetFQDNs = Field(
        description=(
            "Root domains to scope the read to. Netblocks are two graph"
            " hops out - hostname to address to announced prefix - so this"
            " answers 'what ranges does this target sit in'."
        ),
    )
    since: str | None = Field(
        default=None,
        description="Only netblocks seen within this window, e.g. ``7d``, ``2w``.",
    )


@cyber_tool("Read Amass Netblocks", args_schema=_AmassNetblocksArgs)
def amass_netblocks_tool(
    domains: list[FQDN],
    since: str | None = None,
) -> list[Netblock]:
    """
    Read the announced address prefixes containing the addresses OWASP Amass
    found for these domains. Sends no traffic.

    Useful for judging whether hosts share infrastructure, and for spotting
    ranges the target owns outright versus addresses inside a provider's
    space. A netblock being listed does NOT put it in scope - scope is the
    programme's, and only the hostnames it names are in it.
    """
    if not domains:
        return []
    return amass_netblocks([str(domain) for domain in domains], AmassFilters(since=since))
