"""
tools/recon_host_store.py - the per-host workspace artefact store.

Every in-scope FQDN gets one directory under ``<run_dir>/assets/<fqdn>/``,
and this module is the typed reader/writer pair for the facets that hang
off it - the on-disk form of one amass FQDN-asset node:

* ``insight.json`` - the OSINT Analyst's full ``HostInsight`` annotation.
* ``host.json`` - the ``HostScore`` (role + priority), the machine-
  actionable curation split out of the prose.
* ``notes.md`` - the agent's "look here, because ..." rationale.
* ``tls.json`` - the leaf ``TLSCertificate`` observed on the host.
* ``ports.json`` / ``findings.json`` - the host's open ports and its
  node-local ``RawFinding`` rows.
* ``services.json`` / ``products.json`` / ``product_releases.json`` /
  ``urls.json`` - the host's OAM asset facets.
* ``relations.json`` - the typed edges originating from this host.

The per-host dirs live under ``<run_dir>/assets/<fqdn>/``; the run-level,
infrastructure OAM assets (one IP serving many FQDNs - AutonomousSystem /
Netblock / Organization / ... ) sit beside them at ``<run_dir>/assets/*.json``.

Split out of ``tools.recon_insights`` (which keeps the validation + the
``finalise_recon`` orchestration that *drives* these writers) so neither
module outgrows its single responsibility. Each ``save_X`` / ``load_X``
pair is a writer/reader workspace contract; the JSON shapes are what #45
swaps for amass inserts.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import TypeAdapter

import runtime
from models import (
    HostInsight,
    HostScore,
    Product,
    ProductRelease,
    RawFinding,
    Relation,
    Service,
    TLSCertificate,
    Url,
)
from models.primitives import FQDN

_ASSETS_SUBDIR = "assets"

# FQDNs must be made filesystem-safe before persisting under
# ``assets/<fqdn>/``. The replacement is reversible because we never
# reverse it - the persisted artefacts carry the original hostname in
# their body.
_HOSTNAME_SANITISE = re.compile(r"[^A-Za-z0-9.\-_]")


def _assets_dir() -> Path:
    return runtime.run_dir() / _ASSETS_SUBDIR


def host_dir(hostname: FQDN) -> Path:
    """Return the per-host evidence directory under ``<run_dir>/assets/``.

    Each in-scope FQDN gets its own directory; ``insight_path`` writes
    ``insight.json`` here, and future evidence-writing tools (httpx
    screenshots, nmap output, response bodies) hang their per-host
    artefacts off the same dir. The layout maps cleanly onto an amass
    FQDN asset's worth of input: one directory = one node's evidence
    trail.

    Sanitises the hostname for filesystem use. The replacement is
    reversible because we never reverse it - the persisted artefacts
    inside carry the original hostname in their body.

    The sanitiser keeps ``.`` (legitimate in an FQDN), so a hostname of
    ``.`` / ``..`` would survive and resolve the directory out of (or up
    from) ``assets/``. That matters because a host here is not always a
    validated ``FQDN``: callers also derive it from a ``RawFinding.target``
    (a bare ``str``) or a parsed URL host, both attacker-influenceable. We
    reject the dot-only forms and assert the result stays inside
    ``assets/`` so a crafted host cannot clobber a run-level artefact.
    """
    assets = _assets_dir()
    safe = _HOSTNAME_SANITISE.sub("_", hostname.strip().lower())
    if not safe.strip("_") or safe in {".", ".."}:
        raise ValueError(f"hostname is empty or unsafe after sanitisation: {hostname!r}")
    result = assets / safe
    if not result.resolve().is_relative_to(assets.resolve()):
        raise ValueError(f"hostname escapes the assets directory: {hostname!r}")
    return result


def insight_path(hostname: FQDN) -> Path:
    """Return the on-disk path of the insight for ``hostname``.

    The insight lives at ``<host_dir>/insight.json`` - one file inside
    the host's per-FQDN directory. Sibling files (screenshots, scan
    output, response bodies) land alongside as recon tools write them.
    """
    return host_dir(hostname) / "insight.json"


def save_insight(insight: HostInsight) -> Path:
    """Persist an insight to ``<run_dir>/assets/<host>/insight.json``."""
    path = insight_path(insight.hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(insight.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_insights() -> list[HostInsight]:
    """Load every insight in the current run, ordered by hostname."""
    dir_ = _assets_dir()
    if not dir_.is_dir():
        return []
    return sorted(
        (
            HostInsight.model_validate_json(p.read_text(encoding="utf-8"))
            for p in dir_.glob("*/insight.json")
        ),
        key=lambda i: i.hostname,
    )


def tls_path(hostname: FQDN) -> Path:
    """Return the on-disk path of the TLS cert for ``hostname``.

    The cert lives at ``<host_dir>/tls.json`` - the per-host sibling of
    ``insight.json``, the leaf certificate hanging off the host's
    per-FQDN directory the way ``host_dir`` reserves room for.
    """
    return host_dir(hostname) / "tls.json"


def save_tls_certificate(certificate: TLSCertificate) -> Path:
    """Persist a cert to ``<run_dir>/assets/<host>/tls.json``."""
    path = tls_path(certificate.host)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(certificate.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_tls_certificates() -> list[TLSCertificate]:
    """Load every per-host TLS cert in the current run, ordered by host."""
    dir_ = _assets_dir()
    if not dir_.is_dir():
        return []
    return sorted(
        (
            TLSCertificate.model_validate_json(p.read_text(encoding="utf-8"))
            for p in dir_.glob("*/tls.json")
        ),
        key=lambda c: c.host,
    )


# Typed adapters for the per-host facet files that hold bare collections
# rather than a single model - so the JSON still round-trips through a
# typed boundary (the #45 amass-read side validates the same way).
_HOST_FINDINGS = TypeAdapter(list[RawFinding])
_HOST_PORTS = TypeAdapter(list[int])
_HOST_SERVICES = TypeAdapter(list[Service])
_HOST_URLS = TypeAdapter(list[Url])
_HOST_RELATIONS = TypeAdapter(list[Relation])
_HOST_PRODUCTS = TypeAdapter(list[Product])
_HOST_PRODUCT_RELEASES = TypeAdapter(list[ProductRelease])


def host_score_path(hostname: FQDN) -> Path:
    """Per-host score file: ``<host_dir>/host.json``."""
    return host_dir(hostname) / "host.json"


def save_host_score(score: HostScore) -> Path:
    """Persist a ``HostScore`` to ``<run_dir>/assets/<host>/host.json``."""
    path = host_score_path(score.hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(score.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_host_scores() -> list[HostScore]:
    """Load every per-host score in the current run, ordered by hostname."""
    dir_ = _assets_dir()
    if not dir_.is_dir():
        return []
    return sorted(
        (
            HostScore.model_validate_json(p.read_text(encoding="utf-8"))
            for p in dir_.glob("*/host.json")
        ),
        key=lambda s: s.hostname,
    )


def notes_path(hostname: FQDN) -> Path:
    """Per-host prose file: ``<host_dir>/notes.md``."""
    return host_dir(hostname) / "notes.md"


def save_host_notes(hostname: FQDN, notes: str) -> Path:
    """Persist the OA's prose guidance to ``<run_dir>/assets/<host>/notes.md``.

    The "look here, because ..." half of the curation, kept as markdown
    outside the typed data shape. Agent-authored prose: it is read back by
    downstream agents as workspace context (that is the point of the
    handoff), so no injection guard - the risk surface is *verbatim
    tool-captured* strings, which live in the typed evidence facets
    (findings / tls), not here.
    """
    path = notes_path(hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(notes, encoding="utf-8")
    return path


def findings_path(hostname: FQDN) -> Path:
    """Per-host findings file: ``<host_dir>/findings.json``."""
    return host_dir(hostname) / "findings.json"


def save_host_findings(hostname: FQDN, findings: list[RawFinding]) -> Path:
    """Persist a host's node-local findings to ``hosts/<host>/findings.json``."""
    path = findings_path(hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_HOST_FINDINGS.dump_json(findings, indent=2))
    return path


def load_host_findings(hostname: FQDN) -> list[RawFinding]:
    """Load a host's node-local findings; empty when none were written."""
    path = findings_path(hostname)
    if not path.is_file():
        return []
    return _HOST_FINDINGS.validate_json(path.read_text(encoding="utf-8"))


def ports_path(hostname: FQDN) -> Path:
    """Per-host open-ports file: ``<host_dir>/ports.json``."""
    return host_dir(hostname) / "ports.json"


def save_host_ports(hostname: FQDN, ports: list[int]) -> Path:
    """Persist a host's open ports to ``hosts/<host>/ports.json``."""
    path = ports_path(hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_HOST_PORTS.dump_json(ports, indent=2))
    return path


def load_host_ports(hostname: FQDN) -> list[int]:
    """Load a host's open ports; empty when none were written."""
    path = ports_path(hostname)
    if not path.is_file():
        return []
    return _HOST_PORTS.validate_json(path.read_text(encoding="utf-8"))


def services_path(hostname: FQDN) -> Path:
    """Per-host services file: ``<host_dir>/services.json``."""
    return host_dir(hostname) / "services.json"


def save_host_services(hostname: FQDN, services: list[Service]) -> Path:
    """Persist a host's ``Service`` assets to ``hosts/<host>/services.json``.

    The OAM ``Service``-asset facet of the host node: one open service per
    row, each carrying its banner detail, the NIST CPE nmap matched, and
    the detecting tool. The on-disk form of what #45 upserts as amass
    Service nodes hanging off the FQDN.
    """
    path = services_path(hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_HOST_SERVICES.dump_json(services, indent=2))
    return path


def load_host_services(hostname: FQDN) -> list[Service]:
    """Load a host's ``Service`` assets; empty when none were written."""
    path = services_path(hostname)
    if not path.is_file():
        return []
    return _HOST_SERVICES.validate_json(path.read_text(encoding="utf-8"))


def urls_path(hostname: FQDN) -> Path:
    """Per-host URLs file: ``<host_dir>/urls.json``."""
    return host_dir(hostname) / "urls.json"


def save_host_urls(hostname: FQDN, urls: list[Url]) -> Path:
    """Persist a host's OAM ``Url`` assets to ``hosts/<host>/urls.json``.

    The OAM ``URL``-asset facet of the host node: one structured URL per row
    (scheme / host / port / path / ...), the on-disk form of what #45 upserts
    as amass URL nodes related to the FQDN. Sibling of ``services.json``.
    """
    path = urls_path(hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_HOST_URLS.dump_json(urls, indent=2))
    return path


def load_host_urls(hostname: FQDN) -> list[Url]:
    """Load a host's ``Url`` assets; empty when none were written."""
    path = urls_path(hostname)
    if not path.is_file():
        return []
    return _HOST_URLS.validate_json(path.read_text(encoding="utf-8"))


def products_path(hostname: FQDN) -> Path:
    """Per-host products file: ``<host_dir>/products.json``."""
    return host_dir(hostname) / "products.json"


def save_host_products(hostname: FQDN, products: list[Product]) -> Path:
    """Persist a host's OAM ``Product`` assets to ``hosts/<host>/products.json``.

    The product lines nmap's CPEs decomposed to (e.g. ``nginx``), linked to
    their services by ``product_used`` edges in ``relations.json``.
    """
    path = products_path(hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_HOST_PRODUCTS.dump_json(products, indent=2))
    return path


def load_host_products(hostname: FQDN) -> list[Product]:
    """Load a host's ``Product`` assets; empty when none were written."""
    path = products_path(hostname)
    if not path.is_file():
        return []
    return _HOST_PRODUCTS.validate_json(path.read_text(encoding="utf-8"))


def product_releases_path(hostname: FQDN) -> Path:
    """Per-host product-releases file: ``<host_dir>/product_releases.json``."""
    return host_dir(hostname) / "product_releases.json"


def save_host_product_releases(hostname: FQDN, releases: list[ProductRelease]) -> Path:
    """Persist a host's OAM ``ProductRelease`` assets to ``product_releases.json``.

    The version-specific releases (e.g. ``nginx 1.25.3``) - the spec-proper
    anchor the VR's CPE -> CVE ``VulnProperty`` results hang off.
    """
    path = product_releases_path(hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_HOST_PRODUCT_RELEASES.dump_json(releases, indent=2))
    return path


def load_host_product_releases(hostname: FQDN) -> list[ProductRelease]:
    """Load a host's ``ProductRelease`` assets; empty when none were written."""
    path = product_releases_path(hostname)
    if not path.is_file():
        return []
    return _HOST_PRODUCT_RELEASES.validate_json(path.read_text(encoding="utf-8"))


def relations_path(hostname: FQDN) -> Path:
    """Per-host relations file: ``<host_dir>/relations.json``."""
    return host_dir(hostname) / "relations.json"


def save_host_relations(hostname: FQDN, relations: list[Relation]) -> Path:
    """Persist a host's OAM graph edges to ``hosts/<host>/relations.json``.

    The explicit-edge half of the host's OAM subgraph: assets carry their own
    attached properties in their facet files; the typed relations *between*
    them (host -> ``Service`` ``port``, ``Service`` -> ``ProductRelease``
    ``product_used``, ...) live here, one record per edge. #45 inserts one
    graph edge per row.
    """
    path = relations_path(hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_HOST_RELATIONS.dump_json(relations, indent=2))
    return path


def load_host_relations(hostname: FQDN) -> list[Relation]:
    """Load a host's OAM graph edges; empty when none were written."""
    path = relations_path(hostname)
    if not path.is_file():
        return []
    return _HOST_RELATIONS.validate_json(path.read_text(encoding="utf-8"))


__all__ = [
    "findings_path",
    "host_dir",
    "host_score_path",
    "insight_path",
    "load_host_findings",
    "load_host_ports",
    "load_host_product_releases",
    "load_host_products",
    "load_host_relations",
    "load_host_scores",
    "load_host_services",
    "load_host_urls",
    "load_insights",
    "load_tls_certificates",
    "notes_path",
    "ports_path",
    "product_releases_path",
    "products_path",
    "relations_path",
    "save_host_findings",
    "save_host_notes",
    "save_host_ports",
    "save_host_product_releases",
    "save_host_products",
    "save_host_relations",
    "save_host_score",
    "save_host_services",
    "save_host_urls",
    "save_insight",
    "save_tls_certificate",
    "services_path",
    "tls_path",
    "urls_path",
]
