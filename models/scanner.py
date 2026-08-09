"""
models/scanner.py - typed shapes for CLI-scanner config + results.

Carries the agent-facing knobs the OA picks per invocation (modes,
banner depth, NSE script bundles) and the result-of-a-scan shapes
those invocations emit. Distinct from ``models/network.py`` which
holds asset-layer network properties (ASN / Netblock / RIR Org /
future RDAP) - that file describes the asset, this file describes
the scan.

Both nmap and httpx live here. Future amass-tool wrappers and any
later CLI binary the OA reaches for (naabu, wafw00f, gowitness)
add their shape here too. The pattern they share: a Mode enum the
agent reasons in, a Result model the agent reads back, optional
evidence-path field for things written to ``runtime.run_dir()``.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from models.asset import Endpoint
from models.primitives import FQDN, IpAddr


class NmapMode(StrEnum):
    """Coarse scan profile the OA picks per nmap invocation.

    Each mode is a *what kind of question is this scan asking*, not the
    flag-list directly. The wrapper composes the actual nmap flags from
    ``(mode, banner, scripts, config.scan.scan_mode)`` - the OA reasons
    in modes, not in CLI args.
    """

    QUICK_PORTS = "quick-ports"  # top-100 TCP SYN scan; ports only
    SERVICE_VERSION = "service-version"  # adds -sV banner-grabbing
    FULL_INVENTORY = "full-inventory"  # service-version + NSE scripts
    OS_DETECT = "os-detect"  # -O OS fingerprint; privileged only


class NmapBanner(StrEnum):
    """Banner-grabbing depth within ``SERVICE_VERSION`` / ``FULL_INVENTORY``.

    Orthogonal to ``NmapMode``: the OA can pick SERVICE_VERSION + LIGHT
    for stealth, or FULL_INVENTORY + FULL for a deep selective sweep.
    Maps to nmap's ``--version-intensity`` knob (0-9).
    """

    NONE = "none"  # no banner grab; ignored when mode == QUICK_PORTS
    LIGHT = "light"  # --version-intensity 2 (quiet)
    FULL = "full"  # --version-intensity 9 (thorough; loud)


class NmapScripts(StrEnum):
    """NSE (Nmap Scripting Engine) bundle the OA opts into.

    Each member maps to nmap's ``--script=<expr>`` argument.
    ``HTTP_HEADERS`` is a narrow web-recon set; ``DEFAULT`` is nmap's
    ``-sC`` (the ``default`` NSE category, run as ``--script=default``)
    - the safe-by-design banner / service-detail bundle the focused
    "deep scan a host's known-open ports" pass reaches for; ``SAFE`` is
    nmap's broader ``safe`` category (no exploitation, low noise);
    ``VULN`` runs the ``vuln`` category which actively probes for known
    CVEs - loud, refused under ``ScanMode.STEALTH`` by the wrapper.
    """

    NONE = "none"
    HTTP_HEADERS = "http-headers"  # --script=banner,http-server-header,http-title
    DEFAULT = "default"  # --script=default; nmap's -sC default-script category
    SAFE = "safe"  # --script=safe
    VULN = "vuln"  # --script=vuln


class NmapService(BaseModel):
    """One open port + (optional) service banner on a single host.

    Carries what nmap's XML output puts in a ``<port>`` element:
    port number, transport protocol, port state, plus the four
    banner fields from the ``<service>`` child when ``-sV`` ran.
    """

    port: int = Field(ge=1, le=65535)
    protocol: str = Field(max_length=8)  # "tcp" / "udp"
    state: str = Field(max_length=16)  # "open" / "filtered" / "closed" / ...

    # Tool-captured from nmap's service-version output. Defence: each
    # field carries a boundary length cap so a malformed banner cannot
    # smuggle a large injection through the OA -> Service translation.
    service: str | None = Field(default=None, max_length=64)
    product: str | None = Field(default=None, max_length=128)
    version: str | None = Field(default=None, max_length=64)
    extra_info: str | None = Field(default=None, max_length=255)

    # nmap's service-detection confidence for this match (the ``<service conf>``
    # attribute), 1-10; 0 when nmap emitted no match. The producer scales it to
    # the OAM ``SourceProperty.confidence`` (0-100) it stamps on the Service /
    # Product / ProductRelease assets.
    conf: int = Field(default=0, ge=0, le=10)

    # Tool-captured CPE 2.3 string, normalised from nmap's ``<cpe>`` 2.2 URI
    # output via ``tools.cpe.normalize_cpe``. The product's NIST identifier
    # and the high-confidence join key for the VR's CVE lookup. ``None`` when
    # nmap emitted no CPE for the port (no ``-sV`` match, or a service-name-
    # only guess from the port number). Same boundary length cap as the
    # banner fields above.
    #
    # FIXME(#45 / amass-integration): promote to a typed ``Cpe`` primitive in
    # ``models.primitives`` once the CVE-lookup workflow lands - CPE now sits
    # on two fields (here + ``Service.cpe``), the multi-field threshold the
    # cybersquad-models skill sets for a primitive.
    cpe: str | None = Field(default=None, max_length=255)


class NmapHostResult(BaseModel):
    """The per-host slice of an nmap scan result.

    Carries the host identity (the FQDN or IP nmap was asked to scan; the
    parser surfaces whichever address it returned) and the list of
    discovered services. A scanner-internal shape: the OA tool boundary
    translates these into OAM ``Service`` assets before anything crosses
    to the agent.
    """

    host: FQDN | IpAddr
    services: list[NmapService] = Field(default_factory=list)


class NmapScanResult(BaseModel):
    """Typed result of one ``nmap_scan(...)`` invocation.

    Carries the mode the agent asked for, the per-host findings, and -
    when ``persist_evidence`` was True - the relative path to the
    nmap XML file that was written under the run directory. The path
    is what the VR / Technical Author cite as evidence; the structured
    summary is what the agent reads.
    """

    mode: NmapMode
    hosts: list[NmapHostResult] = Field(default_factory=list)
    # When ``persist_evidence=True``, the relative path (under
    # runtime.run_dir()) of the XML file nmap wrote. ``None`` when the
    # scan ran without persisting (lightweight scans the OA does not
    # intend to cite as evidence).
    evidence_path: str | None = Field(default=None, max_length=255)


class HttpxMode(StrEnum):
    """Coarse profile the OA picks per ``httpx_scan`` invocation.

    Same shape as ``NmapMode`` - escalating bundles of httpx-CLI flags.
    The OA's broad-then-narrow pattern is: ``LIVE`` against the whole
    subdomain list to find live HTTP/S endpoints; ``TECH_DETECT`` on
    that subset for Wappalyzer fingerprints + server / title headers;
    ``WEB_INVENTORY`` on the HIGH-priority hosts only - the heavyweight
    pass that grabs the favicon hash (Shodan-pivot) and TLS SAN names
    (in-scope FQDN-discovery surface).

    Deliberately does NOT expose httpx flags that overlap dedicated
    recon tools: ``-asn`` defers to ``tools/recon/asn.py`` (Team Cymru,
    BGP-rooted authoritative source); ``-cname`` defers to
    ``tools/recon/dnsx.py`` (dedicated DNS tool that already chains
    CNAMEs into the takeover-fingerprint flow). One way to get each
    data point.
    """

    LIVE = "live"  # -status-code only; "is this URL alive?"
    TECH_DETECT = "tech-detect"  # + -tech-detect / -server / -title
    WEB_INVENTORY = "web-inventory"  # + -favicon / -tls-grab / -content-type / -method


class HttpxScanResult(BaseModel):
    """Typed result of one ``httpx_scan(...)`` invocation.

    Mirrors ``NmapScanResult`` - structured signal + optional evidence
    pointer. The agent reads ``endpoints`` for the per-host data and
    ``evidence_dir`` for a relative path under ``runtime.run_dir()``
    pointing at the directory httpx wrote screenshot PNGs / stored
    response bodies to. The VR / Technical Author cite files in that
    directory in the report.

    ``evidence_dir`` is ``None`` when neither ``with_screenshots`` nor
    ``with_responses`` was requested or when no pipeline run was bound
    (tests, library usage). When set, the directory exists and contains
    at minimum one PNG (screenshots) or one stored-response file per
    live endpoint.
    """

    mode: HttpxMode
    endpoints: list[Endpoint] = Field(default_factory=list)
    # Relative path under runtime.run_dir() pointing at the directory
    # httpx wrote evidence files to (screenshot PNGs and / or response
    # bodies). None when neither was requested or no run was bound.
    evidence_dir: str | None = Field(default=None, max_length=255)


__all__ = [
    "HttpxMode",
    "HttpxScanResult",
    "NmapBanner",
    "NmapHostResult",
    "NmapMode",
    "NmapScanResult",
    "NmapScripts",
    "NmapService",
]
