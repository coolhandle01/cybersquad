"""
models.asset.service - the OAM ``Service`` / ``Product`` / ``ProductRelease``
assets.

The OAM ``Service`` asset the OA's deep-scan pass emits, plus the product
line and version-specific release the ``product_used`` edge points at (and
the spec-proper anchor a ``VulnProperty`` hangs off).

OAM assets (modelled field-for-field):
* ``Service`` <https://owasp-amass.github.io/docs/open_asset_model/assets/service/>
* ``Product`` <https://owasp-amass.github.io/docs/open_asset_model/assets/product/>
* ``ProductRelease``
  <https://owasp-amass.github.io/docs/open_asset_model/assets/product_release/>

nmap's host:port becomes the ``port`` relation (host -> Service) and its CPE
is decomposed into ``Product`` / ``ProductRelease`` assets linked by a
``product_used`` relation - none of that lives on the ``Service`` struct,
faithful to OAM. The decomposition runs in ``tools/recon/nmap/service.py``.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from models.asset.property import SourceProperty, VulnProperty


class Service(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``Service`` asset.

    One network-accessible service the OSINT Analyst's deep-scan pass (a
    focused nmap ``-sV`` against a host's open ports) observed. Mirrors
    amass's ``Service`` field for field (OAM json tag in parentheses):

    * ``id`` (``unique_id``) -> the service's stable identity. cybersquad
      synthesises it as ``<host>:<port>/<protocol>``.
    * ``type`` (``service_type``) -> the service kind nmap named ("http",
      "ssh", ...).
    * ``output`` (``output``) -> the service-detection banner text.
    * ``output_length`` (``output_length``) -> ``len(output)``.
    * ``attributes`` (``attributes``) -> the remaining nmap banner fields as
      a key -> values map (``product`` / ``version`` / ``cpe``).

    The service's host:port is *not* a field - it is the ``port`` relation
    (host -> Service) in ``relations.json``. The product / version / CPE are
    not fields either - nmap's CPE is decomposed into ``Product`` /
    ``ProductRelease`` assets linked by a ``product_used`` relation, and the
    CPE keys the CVE lookup whose ``VulnProperty`` results hang off the
    release; ``attributes`` keeps the raw nmap values for provenance.

    OAM is a *presence* graph: a ``Service`` exists only where the scan
    observed an open service - a filtered / closed port is absence, not a
    node.
    """

    id: str = Field(min_length=1, max_length=255)  # unique_id ("<host>:<port>/<proto>")
    type: str = Field(default="", max_length=64)  # service_type ("http" / "ssh")

    # Tool-captured nmap service-detection banner. Defence (cybersquad-models
    # skill, tool-captured text): length-capped at the boundary; it flows to
    # the asset graph and the human-facing report, not re-issued to an LLM as
    # instruction context.
    output: str = Field(default="", max_length=2048)  # output
    output_length: int = Field(default=0, ge=0)  # output_length

    # The remaining nmap banner fields, OAM's key -> values bag (product /
    # version / cpe). Tool-captured: same defence posture as ``output`` - the
    # values are nmap output, read as data, never fed back as instructions.
    attributes: dict[str, list[str]] = Field(default_factory=dict)  # attributes

    # OAM ``VulnProperty`` annotations hung off this service. Additive and
    # default-empty; service-level CVEs land here, product-version CVEs on the
    # related ``ProductRelease``.
    vulns: list[VulnProperty] = Field(default_factory=list)

    # OAM ``SourceProperty`` provenance stamps - which tool / feed produced
    # this asset and at what confidence. Additive and default-empty; the
    # producer (nmap) stamps its source at write time.
    sources: list[SourceProperty] = Field(default_factory=list)


class Product(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``Product`` asset.

    A product line / vendor offering observed on the surface - "WordPress",
    "nginx", "Spring Framework". In OAM a ``Service`` relates to a
    ``Product`` via the ``product_used`` edge; the version-specific instance
    is ``ProductRelease`` below. Mirrors amass's ``Product`` field for field
    (OAM json tag in parentheses).
    """

    name: str = Field(min_length=1, max_length=128)  # product_name
    product_id: str = Field(default="", max_length=128)  # unique_id
    type: str = Field(default="", max_length=64)  # product_type
    category: str = Field(default="", max_length=128)  # category
    # Agent- / feed-authored descriptive text; length-capped at the boundary.
    description: str = Field(default="", max_length=2000)  # description
    country_of_origin: str = Field(default="", max_length=64)  # country_of_origin

    # OAM ``SourceProperty`` provenance stamps - which tool / feed produced
    # this asset and at what confidence. Additive and default-empty; the
    # producer (nmap CPE decomposition) stamps its source at write time.
    sources: list[SourceProperty] = Field(default_factory=list)


class ProductRelease(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``ProductRelease`` asset.

    A specific released version of a ``Product`` - "WordPress 5.8.1". In OAM
    this is the spec-proper anchor a ``VulnProperty`` hangs off (a CVE is
    carried by the *release*, not the product line), and the target of a
    ``Service`` ``product_used`` edge. Mirrors amass's ``ProductRelease``
    (OAM json tag in parentheses).
    """

    name: str = Field(min_length=1, max_length=128)  # name (e.g. "WordPress 5.8.1")
    release_date: str = Field(default="", max_length=64)  # release_date (verbatim)

    # OAM ``VulnProperty`` annotations hung off this release - the
    # spec-proper home for a CVE the VR matched against this exact version.
    # Additive and default-empty.
    vulns: list[VulnProperty] = Field(default_factory=list)

    # OAM ``SourceProperty`` provenance stamps - which tool / feed produced
    # this asset and at what confidence. Additive and default-empty; the
    # producer (nmap CPE decomposition) stamps its source at write time.
    sources: list[SourceProperty] = Field(default_factory=list)
