"""
models.asset.certificate - the OAM ``TLSCertificate`` asset shape.

One X.509 leaf certificate as observed on a host's HTTPS service. A leaf
shape (primitives only) the endpoint and graph modules compose.

OAM asset:
<https://owasp-amass.github.io/docs/open_asset_model/assets/tls_certificate/>
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from models.primitives import FQDN, IpAddr


class TLSCertificate(BaseModel):
    """The cybersquad shape that maps to amass's ``TLSCertificate`` asset.

    One X.509 leaf certificate as observed on a host's HTTPS service -
    what httpx's ``-tls-grab`` and testssl.sh surface during the OSINT
    Analyst's sweep. Today only the SAN list is harvested (into
    ``Endpoint.tls_sans``, for in-scope-FQDN discovery) and posture
    problems become ``RawFinding`` rows; the cert itself is never
    persisted as an asset. This model is that asset node.

    Carries the cert's *identity and properties*, not its posture:
    subject / issuer / serial / fingerprint / validity window / SANs.
    Posture judgements (self-signed, expired, weak cipher) stay in the
    testssl ``RawFinding`` path - this shape answers "what cert is
    this", the findings answer "what is wrong with it".

    When amass lands (#45), each ``TLSCertificate`` becomes one amass
    ``TLSCertificate`` asset node:

    * ``fingerprint_sha256`` / ``serial`` -> the node's stable identity
      and the natural join key for a Censys / Shodan ``cert hash`` pivot.
    * ``subject_common_name`` / ``issuer`` / ``not_before`` /
      ``not_after`` -> ``SimpleProperty`` values on the node.
    * ``subject_alt_names`` -> ``SAN_FOR`` edges to the ``FQDN`` assets
      the cert vouches for; a multi-SAN cert is the densest single-asset
      FQDN-discovery surface recon produces.
    * ``host`` -> the edge back to the ``FQDN`` / ``IpAddr`` the cert
      was observed on (provenance), mirroring ``Service.host``.

    All fields beyond ``host`` default to None / empty - a cert is
    useful with whatever subset the grab recovered.
    """

    host: FQDN | IpAddr

    # Tool-captured from the leaf cert the *target* presents - i.e.
    # attacker-controlled text. Defence on every field below: a boundary
    # length cap (the cert owner picks these strings, so they are not
    # trustworthy); none are re-issued to an LLM as instruction context,
    # they flow to the asset graph and the human-facing report only.
    subject_common_name: str | None = Field(default=None, max_length=255)
    issuer: str | None = Field(default=None, max_length=255)  # issuing CA CN / org
    serial: str | None = Field(default=None, max_length=128)  # hex serial number
    fingerprint_sha256: str | None = Field(default=None, max_length=128)

    not_before: datetime | None = None  # validity window start
    not_after: datetime | None = None  # validity window end (expiry signal)

    # Subject Alternative Names exactly as the cert lists them. Bare
    # ``list[str]`` (not ``list[FQDN]`` like ``Endpoint.tls_sans``) on
    # purpose: a cert's SANs routinely include wildcards (``*.example.com``)
    # and occasionally ``iPAddress`` entries, which the FQDN validator
    # rejects - and the cert asset must represent the SANs faithfully
    # rather than drop the non-RFC-1123 ones the way the discovery-side
    # ``Endpoint.tls_sans`` does. Same defence posture as
    # ``Endpoint.technologies``: raw external strings, filtered through
    # ``filter_in_scope`` before any are promoted to in-scope hosts, and
    # never fed back to an LLM as instructions.
    subject_alt_names: list[str] = Field(default_factory=list)
