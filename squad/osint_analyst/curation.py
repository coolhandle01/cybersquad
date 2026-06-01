"""
squad/osint_analyst/curation.py - the OSINT curation surface.

Tools the OA uses to turn the in-progress sweep into the canonical
``recon.json`` artefact: cite remediation guidance (CWE / OWASP), label
discovered hosts (role / priority / notes / detected tech), surface
hosts that have not yet been annotated, and consolidate everything into
the typed artefact downstream agents (VR research, PT probes) consume.
"""

from pydantic import BaseModel, Field, TypeAdapter

from models import (
    CWE,
    FQDN,
    HostAnnotation,
    HostInsight,
    HostPriority,
    HostRole,
    OWASPEntry,
    ReconFinalisationError,
    VulnProperty,
)
from squad import cyber_tool
from squad.workspace_tools import current_programme
from tools.owasp_data import lookup as owasp_lookup
from tools.recon.scope import TargetFQDN
from tools.recon_insights import (
    finalise_recon,
    save_insight,
    uncovered_interesting_hosts,
    validate_insight,
)
from tools.recon_insights import (
    load_attack_graph as load_attack_graph_impl,
)
from tools.recon_insights import (
    load_insights as load_insights_impl,
)

# A bare ``FQDN(x)`` call does not run the AfterValidator; validate the
# uncovered-host list through Pydantic so the typed return is real.
_FQDN_LIST_ADAPTER: TypeAdapter[list[FQDN]] = TypeAdapter(list[FQDN])


class _OsintLookupCweArgs(BaseModel):
    """Explicit args_schema for the OSINT Lookup CWE tool."""

    cwe_id: int = Field(
        description=(
            "The CWE id of the weakness class to cite (e.g. ``79`` for"
            " XSS, ``89`` for SQLi, ``94`` for SSTI). When annotating a"
            " host whose detected tech has a well-known weakness, pass"
            " that weakness's id - or the id ``NVD CVE Lookup`` returned"
            " for a matched CVE. Returns MITRE's name + description + URL."
        ),
    )


@cyber_tool("Lookup CWE", args_schema=_OsintLookupCweArgs)
def lookup_cwe_tool(cwe_id: int) -> list[CWE]:
    """
    Resolve a CWE id to MITRE's canonical name, description, and URL - useful
    when annotating a host whose detected tech has a well-known weakness class
    (e.g. WordPress -> XSS / SQLi; Spring Boot -> SSTI / RCE), or to enrich the
    id NVD CVE Lookup returned. Returns one entry, or an empty list if the id
    is not a real CWE.
    """
    cwe = CWE.get(cwe_id)
    return [cwe] if cwe else []


class _OsintLookupOwaspArgs(BaseModel):
    """Explicit args_schema for the OSINT Lookup OWASP Guidance tool."""

    query: str = Field(
        description=(
            "Free-text query against the OWASP Cheat Sheet index. Matches"
            " on cheatsheet title and topic (case-insensitive substring)."
            " Use to surface guidance the Vulnerability Researcher can"
            " reason against when building the attack plan."
        ),
    )


@cyber_tool("Lookup OWASP Guidance", args_schema=_OsintLookupOwaspArgs)
def lookup_owasp_tool(query: str) -> list[OWASPEntry]:
    """
    Find OWASP Cheat Sheet entries for a vuln class or topic - hint for
    the Vulnerability Researcher's attack-plan reasoning. Returns each match's title,
    key_principles, and the canonical cheatsheetseries.owasp.org URL.
    """
    return list(owasp_lookup(query))


class _AnnotateHostArgs(BaseModel):
    """Explicit args_schema for the Annotate Host tool."""

    hostname: TargetFQDN = Field(
        description=(
            "FQDN to annotate. Must already be in the sweep, or have"
            " been surfaced by Discover Subdomains / Discover Historical"
            " URLs / Discover Webpages. Validated as an RFC 1123"
            " hostname (URLs / ports / paths reject upstream)."
        ),
    )
    role: HostRole = Field(
        description=(
            "Functional role this host plays. Drives the Penetration"
            " Tester's prioritisation - admin / auth hosts attract more probe"
            " budget than static / cdn ones. The schema enforces the"
            " enum upstream so an unknown role rejects before the"
            " wrapper body runs."
        ),
    )
    priority: HostPriority = Field(
        description=(
            "Curation signal the PT uses to allocate probe budget."
            " ``high`` means 'spend probes here'; ``skip`` means 'do not"
            " probe this even if reachable'. Must match the threat model"
            " in the notes; the quality gate checks both."
        ),
    )
    notes: str = Field(
        description=(
            ">= 30 characters (>= 60 for high-priority). Explain what the"
            " host is, what tech runs on it, and why it matters (or why"
            " not). Quality gate fires below the length threshold and"
            " when the priority does not match the prose."
        ),
    )
    detected_tech: list[str] | None = Field(
        default=None,
        description=(
            "Ideally with versions ('Spring Boot 2.6.3' beats 'Spring"
            " Boot'). The quality gate warns when the sweep saw tech the"
            " annotation drops - the annotation is meant to be a curation"
            " of what was seen, not an alternate inventory."
        ),
    )
    vulns: list[VulnProperty] | None = Field(
        default=None,
        description=(
            "OAM VulnProperty annotations to hang off this host - known"
            " vulnerabilities attributed to its detected tech (e.g. a CVE"
            " from NVD CVE Lookup matched against 'WordPress 5.8.1'). Each"
            " carries ``id`` (e.g. 'CVE-2022-22965'), and optionally"
            " ``description``, ``source`` ('nvd'), ``category`` (a CWE),"
            " ``enumeration`` ('CVE'), and a ``reference`` URL. Omit when"
            " the host carries no known vulns."
        ),
    )
    attack_graph_path: str = Field(
        default="attack_graph.json",
        description="Relative path to the OA's sweep file. Defaults to ``attack_graph.json``.",
    )


@cyber_tool("Annotate Host", args_schema=_AnnotateHostArgs)
def annotate_host_tool(
    hostname: FQDN,
    role: HostRole,
    priority: HostPriority,
    notes: str,
    detected_tech: list[str] | None = None,
    vulns: list[VulnProperty] | None = None,
    attack_graph_path: str = "attack_graph.json",
) -> HostAnnotation:
    """
    Author one HostInsight for a single hostname and run the quality gate.

    Inputs:
      - hostname: a hostname from the sweep, or one newly discovered via
        Discover Subdomains / Discover Historical URLs / Discover Webpages
      - role: one of admin, api, auth, app, cdn, static, mail, infra, dev,
        unknown
      - priority: one of high, medium, low, skip - the curation signal the
        Penetration Tester uses to allocate probe budget
      - notes: >= 30 chars (>= 60 for high-priority), explaining what the
        host is, what tech runs on it, and why it matters (or does not)
      - detected_tech: ideally with versions ("Spring Boot 2.6.3" beats
        "Spring Boot"); the warning fires when the sweep saw tech that the
        annotation drops

    Returns a HostAnnotation with the relative insight path and an
    InsightValidationReport. Re-run with the issues addressed when
    validation.ok is false.
    """
    sweep = load_attack_graph_impl(attack_graph_path)
    programme = current_programme()

    insight = HostInsight(
        hostname=hostname.strip().lower(),
        role=HostRole(role),
        priority=HostPriority(priority),
        notes=notes.strip(),
        detected_tech=[t.strip() for t in (detected_tech or []) if t.strip()],
        vulns=[VulnProperty.model_validate(v) for v in (vulns or [])],
    )
    path = save_insight(insight)
    return HostAnnotation(
        path=str(path.relative_to(path.parents[1])),
        validation=validate_insight(insight, sweep, programme),
    )


class _ListUncoveredHostsArgs(BaseModel):
    """Explicit args_schema for the List Uncovered Hosts tool."""

    attack_graph_path: str = Field(
        default="attack_graph.json",
        description=(
            "Relative path to the OA's sweep file. Defaults to"
            " ``attack_graph.json``. Returns interesting-status hostnames (200,"
            " 301, 302, 401, 403, ...) in the sweep that have no insight"
            " yet - use as a checklist before Finalise Recon."
        ),
    )


@cyber_tool("List Uncovered Hosts", args_schema=_ListUncoveredHostsArgs)
def list_uncovered_hosts_tool(attack_graph_path: str = "attack_graph.json") -> list[FQDN]:
    """
    Return interesting-status hostnames in the sweep (200, 301, 302, 401,
    403, ...) that have no insight yet, as typed FQDNs. Use as a checklist
    before calling Finalise Recon - hosts you choose to leave uncovered
    should at least be a deliberate decision.
    """
    sweep = load_attack_graph_impl(attack_graph_path)
    insights = load_insights_impl()
    # Validate + normalise to typed FQDNs through Pydantic - a bare
    # ``FQDN(x)`` call does not run the AfterValidator. The hosts come from
    # parsed in-scope endpoint URLs, so they are already well-formed.
    return _FQDN_LIST_ADAPTER.validate_python(uncovered_interesting_hosts(sweep, insights))


class _FinaliseReconArgs(BaseModel):
    """Explicit args_schema for the Finalise Recon tool."""

    attack_graph_path: str = Field(
        default="attack_graph.json",
        description="Relative path to the OA's sweep file. Defaults to ``attack_graph.json``.",
    )


@cyber_tool("Finalise Recon", args_schema=_FinaliseReconArgs)
def finalise_recon_tool(
    attack_graph_path: str = "attack_graph.json",
) -> str:
    """
    Consolidate the sweep + every authored HostInsight into recon.json for
    the Vulnerability Researcher and Penetration Tester. Refuses if no
    insights have been authored, if any insight has unresolved validation
    errors, or if the surface is non-empty but no host has been marked
    HIGH priority. Returns the bare filename ``recon.json`` on success.
    """
    programme = current_programme()
    try:
        path = finalise_recon(programme, attack_graph_filename=attack_graph_path)
    except ReconFinalisationError as exc:
        raise ValueError(str(exc)) from exc
    return path.name


# Helpers
