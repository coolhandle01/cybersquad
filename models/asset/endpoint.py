"""
models.asset.endpoint - discovered HTTP/S endpoints and the LLM-endpoint marker.

The recon-discovery shapes the OSINT Analyst's httpx pass produces, plus the
paginated slice the recon query tools return.

``Endpoint`` is a cybersquad recon *observation*, not an OAM asset type: the
OAM asset for a web address is ``URL`` (modelled in ``models.asset.url``), and
the status / tech / TLS / vulns an ``Endpoint`` carries become properties hung
off that ``URL`` when #45 lands.
<https://owasp-amass.github.io/docs/open_asset_model/assets/url/>
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from models.asset.certificate import TLSCertificate
from models.asset.property import SourceProperty, VulnProperty
from models.primitives import FQDN, HttpUrl


class Endpoint(BaseModel):
    """A discovered HTTP/S endpoint.

    ``url`` is validated through Pydantic's built-in ``HttpUrl``
    (canonical RFC-3986 parser) with the host component running through
    the ``FQDN`` validator for RFC 1123 strictness; runtime stays
    ``str`` so consumers that ``.startswith(...)`` / ``.lower()`` /
    ``urlparse(ep.url)`` / dict-key / f-string keep working with no
    audit. See ``models/primitives/http_url._validate_endpoint_url`` for the
    full contract.

    ``technologies`` is the raw httpx ``-tech-detect`` output
    (Wappalyzer-shape strings like ``"Django:4.2"``) - the detecting
    tool's own vocabulary, kept verbatim. We classify nothing and
    maintain no catalogue: the tool's string is the identifier. The
    raw strings populate at probe time in ``tools.recon.httpx.httpx_scan``.

    (Web technologies carry no CPE - httpx emits names, not CPEs - so
    they stay as strings here. nmap-discovered services carry their
    NIST CPE on the ``Service`` asset instead.)
    """

    url: HttpUrl
    status_code: int | None = None
    technologies: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)

    # Favicon hash (MMH3 of the favicon bytes) emitted by httpx's
    # ``-favicon`` flag when ``HttpxMode.WEB_INVENTORY`` runs. Used as
    # the join key for Shodan / Censys ``http.favicon.hash:`` searches -
    # one in-scope asset's favicon pivots into every other host serving
    # the same icon. Tool-captured: defence is coerce-time normalise +
    # length cap (MMH3 is a signed 32-bit int rendered as decimal; 12
    # chars including the sign is the realistic ceiling, capped loose).
    favicon_hash: str | None = Field(default=None, max_length=32)
    # TLS Subject Alternative Names extracted from the leaf cert by
    # httpx's ``-tls-grab`` flag when ``HttpxMode.WEB_INVENTORY`` runs.
    # Each entry is an FQDN-shaped string (the FQDN primitive validates
    # at construction). Useful in-scope-FQDN discovery: a multi-SAN cert
    # leaks every hostname the server is authoritative for, which the
    # OA's curation pass can promote to net-new in-scope hosts when
    # the SAN matches the programme's apex.
    tls_sans: list[FQDN] = Field(default_factory=list)
    # The leaf cert observed on this endpoint, as the OAM ``TLSCertificate``
    # asset shape (issuer / validity / fingerprint / full SAN list). Where
    # ``tls_sans`` is the FQDN-typed discovery side-channel (wildcards
    # dropped), this carries the cert faithfully. ``None`` outside
    # ``WEB_INVENTORY`` / when no cert was grabbed. ``run_recon`` lifts
    # these off the endpoints into ``AttackGraph.tls_certificates``.
    tls_certificate: TLSCertificate | None = None

    # FIXME(oam): ``Endpoint`` is a recon *observation*, not an OAM asset, so
    # a ``VulnProperty`` does not belong here - OAM hangs vulns off the ``URL``
    # asset (``models.asset.url.Url.vulns``), which is now the VR's annotation
    # target. This field predates that and has no per-host persistence of its
    # own; remove it once nothing reads ``Endpoint.vulns`` and fold any callers
    # onto ``Url``.
    vulns: list[VulnProperty] = Field(default_factory=list)

    # OAM ``SourceProperty`` provenance stamps - which tool / feed produced
    # this observation and at what confidence. Additive and default-empty; the
    # producer (httpx) stamps its source at write time.
    sources: list[SourceProperty] = Field(default_factory=list)


class EndpointPage(BaseModel):
    """Paginated slice of Endpoint results from a recon query."""

    total: int
    offset: int
    returned: int
    endpoints: list[Endpoint]


class LlmEndpoint(BaseModel):
    """An endpoint flagged as LLM-backed by ``detect_llm_endpoints``.

    A thin wrapper over ``Endpoint`` so the OSINT Analyst tool surface
    carries the LLM-detection intent at the type level (the field set is
    identical, but the model name marks the contract).

    FIXME(#144 / #83): this class is on the way to becoming ``DiscoveredMCP``.
    The intent the original author was reaching for - "this endpoint
    exposes an LLM" - has a more useful concrete shape now that the MCP
    threat model is clear: MCP servers advertise tool lists, capability
    bits, init handshakes, and schemas, and that structured surface is
    what the PT would actually probe against. The right move is to
    promote this into ``models/framework.py`` (per #83) as
    ``DiscoveredMCP`` carrying the advertised tool inventory, the
    suspicious-docstring flags, and the schema-laxness markers that the
    #144 MCP-discipline conversation called out. Until then this class
    exists as an intent marker and a placeholder; do not extend it as a
    generic LLM endpoint shape.
    """

    url: HttpUrl
    status_code: int | None = None
    technologies: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)
