"""
tools/recon_insights.py - Host-annotation authoring primitives for the OSINT
Analyst.

The OA's job is to turn the raw sweep (subfinder + httpx + nmap + dirfuzz +
TLS / DNS checks) into a curated attack-surface map: every interesting host
labelled with a role (admin / api / auth / app / cdn / ...), a priority
(high / medium / low / skip), tech detected with versions where possible, and
free-text notes that tell the Vulnerability Researcher WHY this host warrants
attention. The agent does the curation; this module provides the supporting
primitives:

* ``HostInsight`` (from ``models``) - the agent's working artefact per host.
* ``validate_insight(insight, sweep, programme)`` - quality gate. Returns the
  issue list. Hard errors block ``finalise_recon``.
* ``host_dir(fqdn)`` - the per-host evidence directory under
  ``<run_dir>/assets/<fqdn>/``. Future recon tools (screenshots, scan
  output, response bodies) write per-host artefacts here so each
  directory carries one FQDN asset's worth of evidence end-to-end.
* ``save_insight`` / ``load_insights`` - persist insights under
  ``<run_dir>/assets/<fqdn>/insight.json``.
* ``finalise_recon(programme, attack_graph_filename)`` - load the sweep, validate every
  insight, build the canonical ``AttackGraph`` for downstream agents, and
  write ``recon.json``. Refuses on hard errors or insufficient curation.

The OA's initial sweep is written to ``attack_graph.json``; ``finalise_recon``
copies the inventory through, attaches insights, and emits the final
``recon.json`` that the Vulnerability Researcher and Penetration Tester
consume.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import ValidationError

import runtime
from models import (
    CVE,
    CWE,
    AttackGraph,
    HostInsight,
    HostPriority,
    HostScore,
    ProductRelease,
    RawFinding,
    Service,
    Url,
    VulnProperty,
)
from models.asset.property import VULN_DESCRIPTION_MAX_LENGTH
from models.h1 import Programme

# The insight shapes (HostAnnotation, InsightValidationIssue,
# InsightValidationReport, ReconFinalisationError) live in
# models/insight.py per the typed-shapes-live-in-models rule. Re-
# exported here so existing ``from tools.recon_insights import X``
# consumers keep working; the canonical import path is ``from models
# import X``.
from models.insight import (
    InsightValidationIssue,
    InsightValidationReport,
    ReconFinalisationError,
)
from tools.recon.scope import filter_in_scope

# Per-host workspace I/O moved to tools.recon_host_store. Imported here
# both for finalise's own use and re-exported (via __all__) so existing
# ``from tools.recon_insights import save_insight`` consumers (the
# Annotate Host tool) keep working unchanged.
from tools.recon_host_store import (
    findings_path,
    host_dir,
    host_score_path,
    insight_path,
    load_host_findings,
    load_host_ports,
    load_host_product_releases,
    load_host_scores,
    load_host_services,
    load_host_urls,
    load_insights,
    load_tls_certificates,
    notes_path,
    ports_path,
    save_host_findings,
    save_host_notes,
    save_host_ports,
    save_host_product_releases,
    save_host_score,
    save_host_services,
    save_host_urls,
    save_insight,
    save_tls_certificate,
    tls_path,
)

_ATTACK_GRAPH_FILENAME = "attack_graph.json"
_RECON_FILENAME = "recon.json"


# Validation


def validate_insight(
    insight: HostInsight,
    sweep: AttackGraph,
    programme: Programme,
) -> InsightValidationReport:
    """Apply quality heuristics to a HostInsight. Returns the issue list."""
    issues: list[InsightValidationIssue] = []

    hostname = insight.hostname.strip().lower()
    if not hostname:
        issues.append(
            InsightValidationIssue(
                section="hostname",
                severity="error",
                message="hostname must not be empty",
            )
        )
        return InsightValidationReport(ok=False, issues=issues)

    # Scope: every annotated host must be in scope. Out-of-scope hosts that
    # somehow leaked into the sweep are not the OA's to annotate.
    if not filter_in_scope([hostname], programme):
        issues.append(
            InsightValidationIssue(
                section="hostname",
                severity="error",
                message=(f"{hostname!r} is not in programme scope; only annotate in-scope hosts"),
            )
        )

    # Notes: the whole point. Too short means the agent skipped the
    # curation work.
    if len(insight.notes.strip()) < 30:
        issues.append(
            InsightValidationIssue(
                section="notes",
                severity="error",
                message=(
                    "notes are too short; explain what the host is, what tech "
                    "stack runs on it, and what makes it interesting (or not) "
                    "in 1-3 sentences"
                ),
            )
        )

    # High-priority hosts need a substantive reason.
    if insight.priority == HostPriority.HIGH and len(insight.notes.strip()) < 60:
        issues.append(
            InsightValidationIssue(
                section="notes",
                severity="error",
                message=(
                    "high-priority hosts need >= 60 chars of justification - "
                    "what tech, what surface, why it earns the budget"
                ),
            )
        )

    # SKIP hosts also need a reason - so a downstream reader does not
    # silently re-include them.
    if insight.priority == HostPriority.SKIP and len(insight.notes.strip()) < 30:
        issues.append(
            InsightValidationIssue(
                section="notes",
                severity="error",
                message=(
                    "skip-priority hosts need notes explaining the reason "
                    "(third-party managed, decoy, sensitive, etc.)"
                ),
            )
        )

    # If the host is in the sweep's inventory we expect the agent's
    # detected_tech to either be empty (agent could not enrich) or
    # consistent with what the sweep saw. We only warn on disagreement -
    # the agent can legitimately add versions httpx missed.
    sweep_techs_by_host = _sweep_tech_by_host(sweep)
    if hostname in sweep_techs_by_host:
        sweep_techs = {t.lower() for t in sweep_techs_by_host[hostname]}
        agent_techs = {t.lower() for t in insight.detected_tech}
        # Warn when sweep saw tech the agent did not carry through - might
        # signal the agent ignored a useful signal.
        missing = sweep_techs - {_strip_version(t) for t in agent_techs} - agent_techs
        if missing and len(insight.detected_tech) > 0:
            issues.append(
                InsightValidationIssue(
                    section="detected_tech",
                    severity="warning",
                    message=(
                        f"sweep saw tech the annotation does not carry: "
                        f"{sorted(missing)} - keep, or note explicitly in 'notes' "
                        "that it was deprioritised"
                    ),
                )
            )

    # detected_tech entries should be non-trivial strings.
    for t in insight.detected_tech:
        if len(t.strip()) < 2:
            issues.append(
                InsightValidationIssue(
                    section="detected_tech",
                    severity="error",
                    message=f"tech entry too short to be a real product name: {t!r}",
                )
            )

    ok = not any(i.severity == "error" for i in issues)
    return InsightValidationReport(ok=ok, issues=issues)


def _sweep_tech_by_host(sweep: AttackGraph) -> dict[str, list[str]]:
    """Build a hostname -> tech-list map from the sweep's endpoints."""
    from urllib.parse import urlparse

    by_host: dict[str, list[str]] = {}
    for ep in sweep.endpoints:
        host = (urlparse(ep.url).hostname or "").lower()
        if not host:
            continue
        by_host.setdefault(host, []).extend(ep.technologies)
    return by_host


def _strip_version(tech: str) -> str:
    """Drop trailing version suffixes from a tech string for comparison.

    "WordPress 5.8.1" and "WordPress" should compare equal when checking
    that the agent carried the sweep's tech through.
    """
    return re.sub(r"\s*[0-9][\w.\-]*$", "", tech).strip().lower()


def load_attack_graph(attack_graph_filename: str = _ATTACK_GRAPH_FILENAME) -> AttackGraph:
    """Load the OA's internal sweep artefact."""
    path = runtime.run_dir() / attack_graph_filename
    if not path.is_file():
        raise FileNotFoundError(f"{attack_graph_filename} not found; run Run Initial Sweep first")
    return AttackGraph.model_validate_json(path.read_text(encoding="utf-8"))


def annotate_host_vulns(hostname: str, vulns: list[VulnProperty]) -> HostInsight:
    """Merge OAM ``VulnProperty`` annotations onto an existing host insight.

    The Vulnerability Researcher's hook onto the OAM graph: after an NVD CVE
    lookup matches a host's detected technology, the VR attaches the CVEs as
    ``VulnProperty`` values on that host's FQDN asset. Loads the OA-authored
    insight, appends the vulns the host does not already carry (dedup by
    ``id``), persists, and returns the updated insight.

    Raises ``ValueError`` if the host has no insight yet - the OSINT Analyst
    curates the asset (Annotate Host) before the VR annotates its vulns.
    """
    target = hostname.strip().lower()
    match = next((i for i in load_insights() if i.hostname.strip().lower() == target), None)
    if match is None:
        raise ValueError(
            f"no host insight for {target!r}; the OSINT Analyst must Annotate Host "
            "before the Vulnerability Researcher annotates its vulns"
        )
    existing_ids = {v.id for v in match.vulns}
    merged = list(match.vulns) + [v for v in vulns if v.id not in existing_ids]
    updated = match.model_copy(update={"vulns": merged})
    save_insight(updated)
    return updated


def vuln_from_cve(cve: CVE) -> VulnProperty:
    """Map an NVD ``CVE`` record to the OAM ``VulnProperty`` hung off an asset.

    The bridge from the NVD vocabulary (``models.nvd.CVE``) to the OAM graph
    property the VR persists: ``id`` / ``description`` carry over, ``source``
    is stamped ``"nvd"``, ``enumeration`` ``"CVE"``, ``reference`` is the CVE's
    NVD detail page, and ``category`` names the primary weakness (the first CWE
    NVD attributed that resolves in the MITRE corpus) where the CVE carried one.
    The Annotate <asset> Vulnerability tools convert here so a ``VulnProperty``
    is never hand-built by the agent.

    CWE-name resolution lives here (the tool layer), not on the ``CVE`` model:
    the model stays a flat NVD DTO carrying raw ``cwe_ids``, and we resolve the
    first valid one to a name via ``CWE.get`` only at this boundary.
    """
    primary = next((cwe for cwe_id in cve.cwe_ids if (cwe := CWE.get(cwe_id)) is not None), None)
    category = f"CWE-{primary.cwe_id}: {primary.name}"[:128] if primary else ""
    # The CVE record carries the full advisory; the persisted annotation is a
    # bounded summary - truncate to the field cap here rather than let a long
    # description reject the VulnProperty (the full text stays on the CVE / its
    # reference URL).
    return VulnProperty(
        id=cve.id,
        description=cve.description[:VULN_DESCRIPTION_MAX_LENGTH],
        source="nvd",
        category=category,
        enumeration="CVE",
        reference=cve.url,
    )


def _merge_vulns(existing: list[VulnProperty], incoming: list[VulnProperty]) -> list[VulnProperty]:
    """Append the vulns not already carried (dedup by ``id``), order-preserving."""
    seen = {v.id for v in existing}
    return list(existing) + [v for v in incoming if v.id not in seen]


def annotate_service_vulns(hostname: str, service_id: str, vulns: list[VulnProperty]) -> Service:
    """Merge ``VulnProperty`` annotations onto a host's OAM ``Service`` asset.

    Loads the host's ``services.json``, finds the ``Service`` whose ``id``
    matches, appends the vulns it does not already carry (dedup by ``id``),
    persists, and returns the updated ``Service``. Raises ``ValueError`` when
    the host has no service with that id - List Host Services surfaces the ids.
    """
    target = hostname.strip().lower()
    services = load_host_services(target)
    match = next((s for s in services if s.id == service_id), None)
    if match is None:
        raise ValueError(
            f"no service {service_id!r} on host {target!r}; List Host Services "
            "shows the service ids available to annotate"
        )
    updated = match.model_copy(update={"vulns": _merge_vulns(match.vulns, vulns)})
    save_host_services(target, [updated if s.id == service_id else s for s in services])
    return updated


def annotate_product_release_vulns(
    hostname: str, release_name: str, vulns: list[VulnProperty]
) -> ProductRelease:
    """Merge ``VulnProperty`` annotations onto a host's OAM ``ProductRelease``.

    The spec-proper home for a CVE - the vulnerability belongs to the version.
    Loads the host's ``product_releases.json``, finds the release whose
    ``name`` matches, appends the vulns it does not already carry (dedup by
    ``id``), persists, and returns the updated ``ProductRelease``. Raises
    ``ValueError`` when the host has no release of that name - List Host
    Product Releases surfaces the names.
    """
    target = hostname.strip().lower()
    releases = load_host_product_releases(target)
    match = next((r for r in releases if r.name == release_name), None)
    if match is None:
        raise ValueError(
            f"no product release {release_name!r} on host {target!r}; List Host "
            "Product Releases shows the releases available to annotate"
        )
    updated = match.model_copy(update={"vulns": _merge_vulns(match.vulns, vulns)})
    save_host_product_releases(target, [updated if r.name == release_name else r for r in releases])
    return updated


def annotate_url_vulns(hostname: str, url: str, vulns: list[VulnProperty]) -> Url:
    """Merge ``VulnProperty`` annotations onto a host's OAM ``Url`` asset.

    Loads the host's ``urls.json``, finds the ``Url`` whose ``raw`` matches,
    appends the vulns it does not already carry (dedup by ``id``), persists,
    and returns the updated ``Url``. Raises ``ValueError`` when the host has no
    URL with that raw value.
    """
    target = hostname.strip().lower()
    urls = load_host_urls(target)
    match = next((u for u in urls if u.raw == url), None)
    if match is None:
        raise ValueError(
            f"no URL {url!r} recorded on host {target!r}; annotate a URL the "
            "OSINT Analyst inventoried"
        )
    updated = match.model_copy(update={"vulns": _merge_vulns(match.vulns, vulns)})
    save_host_urls(target, [updated if u.raw == url else u for u in urls])
    return updated


# Finalisation

# Status codes whose hosts deserve an annotation: 2xx is a live target,
# 3xx redirects often hide gates, 401/403 confirm an auth-gated surface
# worth probing. Pure 404/500 we let slide.
_INTERESTING_STATUSES = {200, 201, 204, 301, 302, 307, 308, 401, 403}


def _finding_host(target: str) -> str:
    """Best-effort hostname from a ``RawFinding`` target (URL or bare host)."""
    from urllib.parse import urlparse

    candidate = target if "://" in target else f"//{target}"
    return (urlparse(candidate).hostname or target).strip().lower()


def _url_asset(raw: str) -> Url:
    """Parse a discovered URL string into the OAM ``Url`` asset shape.

    Maps urllib's split components onto the OAM ``URL`` fields (scheme / host
    / port / path / query / fragment / userinfo). Raises ``ValueError`` (bad
    port in the netloc) or ``ValidationError`` (e.g. an over-long raw URL)
    when the result does not fit the ``Url`` shape; ``_materialise_host_dirs``
    skips those rather than abort the run.
    """
    from urllib.parse import urlsplit

    parts = urlsplit(raw)
    return Url(
        raw=raw,
        scheme=parts.scheme,
        host=parts.hostname or "",
        port=parts.port,
        path=parts.path,
        options=parts.query,
        fragment=parts.fragment,
        username=parts.username or "",
        password=parts.password or "",
    )


def _materialise_host_dirs(sweep: AttackGraph, insights: list[HostInsight]) -> None:
    """Write each host's OAM-node directory under ``assets/<fqdn>/``.

    The OA's per-node handoff, split into typed facets so #45 can swap each
    JSON write for an amass insert one day:

    * ``host.json`` / ``notes.md`` - the curation: the typed score+priority,
      and the prose "look here, because ..." lifted out of the data shape.
    * ``ports.json`` / ``findings.json`` / ``tls.json`` / ``urls.json`` - the
      recon facts (the OAM ``Service`` / ``TLSCertificate`` / ``URL`` assets),
      read back off the sweep.

    Dormant facets stay unwritten (empty ports, no certs) rather than
    littering empty files.
    """
    for insight in insights:
        save_host_score(
            HostScore(
                hostname=insight.hostname,
                role=insight.role,
                priority=insight.priority,
                annotated_at=insight.annotated_at,
            )
        )
        save_host_notes(insight.hostname, insight.notes)

    for hostname, ports in sweep.open_ports.items():
        if ports:
            save_host_ports(hostname, ports)

    findings_by_host: dict[str, list[RawFinding]] = {}
    for finding in sweep.passive_findings:
        host = _finding_host(finding.target)
        if host:
            findings_by_host.setdefault(host, []).append(finding)
    for hostname, host_findings in findings_by_host.items():
        save_host_findings(hostname, host_findings)

    for certificate in sweep.tls_certificates:
        save_tls_certificate(certificate)

    urls_by_host: dict[str, list[Url]] = {}
    for endpoint in sweep.endpoints:
        try:
            url_asset = _url_asset(endpoint.url)
        except (ValueError, ValidationError):
            # A malformed / over-long URL must not abort finalisation; skip it.
            continue
        if url_asset.host:
            urls_by_host.setdefault(url_asset.host.lower(), []).append(url_asset)
    for hostname, host_urls in urls_by_host.items():
        save_host_urls(hostname, host_urls)


def finalise_recon(
    programme: Programme,
    attack_graph_filename: str = _ATTACK_GRAPH_FILENAME,
    recon_filename: str = _RECON_FILENAME,
) -> Path:
    """Validate every host insight, merge them with the sweep, and write the
    final ``recon.json`` for downstream agents.

    Refuses to finalise if:
      * no insights have been authored at all (the OA must annotate)
      * any insight has hard validation errors
      * no host has been marked HIGH priority on a non-empty surface (the
        Penetration Tester needs at least one focus target)
      * an insight references a hostname that is not in scope

    Coverage warnings (non-blocking):
      * an interesting-status host in the sweep has no insight
      * a high-priority host is missing detected_tech
    """
    sweep = load_attack_graph(attack_graph_filename)
    insights = load_insights()

    if not insights:
        raise ReconFinalisationError(
            "no host insights have been authored; call Annotate Host for the "
            "interesting hosts in the sweep before finalising"
        )

    failures: list[tuple[str, list[InsightValidationIssue]]] = []
    for insight in insights:
        report = validate_insight(insight, sweep, programme)
        if not report.ok:
            failures.append(
                (
                    insight.hostname,
                    [i for i in report.issues if i.severity == "error"],
                )
            )

    if failures:
        lines = ["one or more host insights have unresolved errors:"]
        for hostname, errs in failures:
            for err in errs:
                lines.append(f"  - insight {hostname} / {err.section}: {err.message}")
        raise ReconFinalisationError("\n".join(lines))

    high_priority = [i for i in insights if i.priority == HostPriority.HIGH]
    if sweep.subdomains and not high_priority:
        raise ReconFinalisationError(
            "no host has been marked HIGH priority; the Penetration Tester "
            "needs at least one focus target on a non-empty surface"
        )

    _materialise_host_dirs(sweep, insights)

    final = AttackGraph(
        programme=sweep.programme,
        subdomains=sweep.subdomains,
        endpoints=sweep.endpoints,
        open_ports=sweep.open_ports,
        technologies=sweep.technologies,
        passive_findings=sweep.passive_findings,
        network_hops=sweep.network_hops,
        # Carry the sweep's enrichment forward - finalise rebuilds the graph by
        # field, so every sweep-gathered field must be relisted here or it is
        # dropped from the PT-facing recon.json (the IP subgraph, the DNS
        # records, the relation edges, the certs).
        ip_enrichment=sweep.ip_enrichment,
        dns_records=sweep.dns_records,
        relations=sweep.relations,
        tls_certificates=sweep.tls_certificates,
        host_insights=insights,
        notes=_build_notes(sweep, insights),
    )

    out_path = runtime.run_dir() / recon_filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(final.model_dump_json(), encoding="utf-8")
    return out_path


def _build_notes(sweep: AttackGraph, insights: list[HostInsight]) -> str:
    """Compose the recon-level notes string from sweep stats + insight tally."""
    by_priority: dict[HostPriority, int] = dict.fromkeys(HostPriority, 0)
    for i in insights:
        by_priority[i.priority] += 1
    return (
        f"sweep: {len(sweep.subdomains)} subdomains, {len(sweep.endpoints)} endpoints; "
        f"insights: {by_priority[HostPriority.HIGH]} high, "
        f"{by_priority[HostPriority.MEDIUM]} medium, "
        f"{by_priority[HostPriority.LOW]} low, "
        f"{by_priority[HostPriority.SKIP]} skip"
    )


# Coverage check (informational)


def uncovered_interesting_hosts(sweep: AttackGraph, insights: list[HostInsight]) -> list[str]:
    """Return interesting-status hostnames in the sweep that have no insight."""
    from urllib.parse import urlparse

    covered = {i.hostname.lower() for i in insights}
    interesting: set[str] = set()
    for ep in sweep.endpoints:
        if ep.status_code in _INTERESTING_STATUSES:
            host = (urlparse(ep.url).hostname or "").lower()
            if host:
                interesting.add(host)
    return sorted(interesting - covered)


__all__ = [
    "InsightValidationIssue",
    "InsightValidationReport",
    "ReconFinalisationError",
    "annotate_host_vulns",
    "annotate_product_release_vulns",
    "annotate_service_vulns",
    "annotate_url_vulns",
    "finalise_recon",
    "findings_path",
    "host_dir",
    "host_score_path",
    "insight_path",
    "load_attack_graph",
    "load_host_findings",
    "load_host_ports",
    "load_host_product_releases",
    "load_host_scores",
    "load_host_services",
    "load_host_urls",
    "load_insights",
    "load_tls_certificates",
    "notes_path",
    "ports_path",
    "save_host_findings",
    "save_host_notes",
    "save_host_ports",
    "save_host_product_releases",
    "save_host_score",
    "save_host_services",
    "save_host_urls",
    "save_insight",
    "save_tls_certificate",
    "tls_path",
    "uncovered_interesting_hosts",
    "validate_insight",
    "vuln_from_cve",
]
