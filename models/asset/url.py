"""
models.asset.url - the OAM ``URL`` asset (a structured, parsed URL).

The addressable *identity* of a URL, broken into scheme / host / port / path /
... - what amass's OAM ``URL`` asset carries. Distinct from ``Endpoint`` (the
sibling module): ``Endpoint`` is a recon *observation* (a URL string plus the
status / technologies / TLS / vulns httpx saw), whereas ``Url`` is the OAM
*asset* - just the identity, with the observations hung off it as properties /
relations when #45 lands.

OAM asset:
<https://owasp-amass.github.io/docs/open_asset_model/assets/url/>
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from models.asset.property import SourceProperty, VulnProperty


class Url(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``URL`` asset.

    A structured, parsed URL - the asset identity, not an opaque string.
    Mirrors amass's ``URL`` field for field (OAM json tag in parentheses):

    * ``raw`` (``url``) -> the raw, unprocessed URL.
    * ``scheme`` (``scheme``) -> http / https / ...
    * ``username`` / ``password`` (``username`` / ``password``) -> userinfo
      credentials embedded in the URL (see the SECURITY note below).
    * ``host`` (``host``) -> the host component (FQDN or IP literal).
    * ``port`` (``port``) -> the port, ``None`` when the URL omits it.
    * ``path`` (``path``) -> the path component.
    * ``options`` (``options``) -> the query string / connect options.
    * ``fragment`` (``fragment``) -> the URI fragment.

    ``host`` is a bare ``str`` (not the ``FQDN`` primitive) on purpose: a URL
    host is legitimately an IPv4 / IPv6 / IDN-punycode literal as well as an
    FQDN, and OAM keeps it an open string - the parse that produced these
    components already validated the shape upstream.
    """

    # The raw URL the components were parsed from - the asset's natural key.
    raw: str = Field(min_length=1, max_length=2048)  # url

    scheme: str = Field(default="", max_length=16)  # scheme
    host: str = Field(default="", max_length=255)  # host (FQDN or IP literal)
    port: int | None = Field(default=None, ge=1, le=65535)  # port (None when omitted)
    path: str = Field(default="", max_length=2048)  # path
    options: str = Field(default="", max_length=2048)  # options (query string)
    fragment: str = Field(default="", max_length=1024)  # fragment

    # Userinfo credentials embedded in the URL. SECURITY (cybersquad-models
    # skill, defence #3 - keep out of LLM context): these are secrets. They
    # are modelled for OAM fidelity, length-capped at the boundary, and must
    # be redacted before a ``Url`` is surfaced to an agent or written into a
    # human-facing report - never re-issue them as instruction context.
    username: str = Field(default="", max_length=255)  # username
    password: str = Field(default="", max_length=255)  # password

    # OAM ``VulnProperty`` annotations hung off this URL asset. Additive and
    # default-empty; the Vulnerability Researcher attaches CVEs here when a
    # vulnerability is URL-scoped rather than service- or release-scoped. OAM
    # lets a ``VulnProperty`` hang off the ``URL`` node like any other asset.
    vulns: list[VulnProperty] = Field(default_factory=list)

    # OAM ``SourceProperty`` provenance stamps - which tool / feed produced
    # this asset and at what confidence. Additive and default-empty; the
    # producer (httpx) stamps its source at write time.
    sources: list[SourceProperty] = Field(default_factory=list)
