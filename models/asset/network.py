"""
models.asset.network - typed shapes for the OAM registrant / network assets
of an attack surface.

Sits between ``models.primitives.IpAddr`` (the typed address) and
``models.asset`` (the FQDN / Endpoint layer agents reason about). The
data here is what Team Cymru bulk-whois, RDAP lookups, and (eventually)
amass's graph emit about the IP-layer ownership of an asset.

Mid-migration to the faithful per-OAM-type modules: the faithful
``IPAddress`` / ``AutonomousSystem`` / ``Netblock`` assets live here now (amass
groups all three in its ``network`` package). The legacy cybersquad
compositions (``AsnRecord`` / ``Contact`` / ``ContactRole`` / ``RdapRecord``)
remain until the recon producers are rewired onto the faithful assets (in
``registration`` / ``org`` / ``contact`` / ``people`` / ``identifier``) plus
``Relation`` edges - then they are removed.

OAM assets:
* ``IPAddress``
  <https://owasp-amass.github.io/docs/open_asset_model/assets/ip_address/>
* ``AutonomousSystem``
  <https://owasp-amass.github.io/docs/open_asset_model/assets/autonomous_system/>
* ``Netblock`` <https://owasp-amass.github.io/docs/open_asset_model/assets/netblock/>

``RdapRecord`` is the structured-registrant sibling of ``AsnRecord``.
RFC 7483 / RDAP gives us per-field registrant_organisation /
abuse_email / registered_at / last_changed_at rather than Cymru's
single stringly-typed organisation field. Each field becomes a separate
amass ``SimpleProperty`` on the ``RIROrganization`` asset; the agent
reads them individually rather than parsing a concatenation. The
``RdapRecord`` here is the runtime in-memory shape; the
``RIROrganization`` properties at amass-write time are the persisted
shape. Two layers, one record.

Distinct from ``models/scanner.py`` - that file carries the CLI
scanner config (NmapMode / HttpxMode / scan-result shapes). This file
describes the asset; ``scanner.py`` describes the scan.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator

from models.asset.property import SourceProperty, VulnProperty
from models.primitives import Cidr, Email, IpAddr, IPType


class IPAddress(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``IPAddress`` asset.

    A single IP-address node. Mirrors amass's ``IPAddress`` field for field
    (OAM json tag in parentheses): ``address`` (``address``) and ``type``
    (``type`` - "IPv4" / "IPv6", determined by the address family). The legacy
    ``IpAddr`` primitive (renamed off this asset's name) validates the literal.
    """

    address: IpAddr  # address
    type: IPType  # type ("IPv4" / "IPv6") - exhaustive; must match address family

    # OAM VulnProperty annotations hung off this IP node (additive, default-empty).
    vulns: list[VulnProperty] = Field(default_factory=list)
    # OAM SourceProperty provenance - which tool / feed surfaced this IP.
    sources: list[SourceProperty] = Field(default_factory=list)

    @model_validator(mode="after")
    def _type_matches_address(self) -> IPAddress:
        """``type`` is fully determined by ``address``'s family (the ``IpAddr``
        primitive already validated the literal), so a ``type`` that disagrees
        with ``address`` is a producer bug we reject rather than persist.
        """
        import ipaddress

        version = ipaddress.ip_address(self.address).version
        expected = IPType.IPV6 if version == 6 else IPType.IPV4
        if self.type != expected:
            raise ValueError(
                f"type {self.type!r} does not match address {self.address!r} (expected {expected})"
            )
        return self


class AutonomousSystem(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``AutonomousSystem``.

    The BGP autonomous system an IP's prefix is announced by. OAM models it as
    just its number; the registrant detail is a related ``AutnumRecord`` and
    ``Organization``. Mirrors amass field for field (OAM json tag in
    parentheses).
    """

    number: int = Field(ge=0, le=4_294_967_295)  # number (32-bit ASN per RFC 6793)


class Netblock(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``Netblock`` asset.

    The announced address prefix an IP is contained by. ``cidr`` is kept as a
    string (amass uses ``netip.Prefix``; cybersquad keeps the CIDR text).
    Mirrors amass field for field (OAM json tag in parentheses).
    """

    cidr: Cidr  # cidr (e.g. "8.8.8.0/24") - validated IPv4/IPv6 network prefix
    type: IPType  # type ("IPv4" / "IPv6") - exhaustive; must match cidr's family

    @model_validator(mode="after")
    def _type_matches_cidr(self) -> Netblock:
        """``type`` is exhaustive (IPv4 / IPv6) and fully determined by
        ``cidr``'s family, so it is required rather than optional - and a
        ``type`` that disagrees with ``cidr`` is a producer bug we reject
        rather than persist (``cidr`` is already canonical via the ``Cidr``
        primitive, so ``ip_network`` here cannot raise).
        """
        import ipaddress

        version = ipaddress.ip_network(self.cidr).version
        expected = IPType.IPV6 if version == 6 else IPType.IPV4
        if self.type != expected:
            raise ValueError(
                f"type {self.type!r} does not match cidr {self.cidr!r} (expected {expected})"
            )
        return self


class AsnRecord(BaseModel):
    """One row of the Team Cymru / RDAP IP-to-ASN lookup result.

    Carries the four data points a Cymru bulk whois returns for a
    given IP: the AS number, the announcing BGP prefix (== netblock),
    the country code, and the registered AS organisation name. RDAP
    can fill the same fields when Cymru is unreachable.

    Maps cleanly to amass's Open Asset Model triple:
    ``IPAddress -> Netblock -> AutonomousSystem``. ``prefix`` is the
    netblock; ``asn`` + ``organisation`` are the AS. Stored together
    here because Cymru returns them as one row - splitting them
    pre-amass adds joins for no gain.
    """

    ip: IpAddr
    asn: int = Field(ge=0, le=4_294_967_295)  # 32-bit ASN range per RFC 6793
    prefix: str = Field(
        max_length=64,
        # CIDR notation, e.g. "1.2.3.0/24" or "2001:db8::/32". Validated
        # up-front by Cymru; we cap length as a boundary defence in case
        # an injection ever slips past Cymru's response shape.
    )
    country: str = Field(
        max_length=8,
        # Two-letter ISO 3166-1 alpha-2 (e.g. "GB", "US"). Capped loose
        # to allow for Cymru's occasional 4-char variants ("EU" / "AP")
        # without rejecting on real-world data.
    )
    organisation: str = Field(
        max_length=255,
        # Tool-captured from Cymru's response. Defence: Cymru emits
        # short trustworthy strings (typically "<AS_NAME>, <CC>"); the
        # length cap is the boundary guard, no further sanitisation
        # needed at this layer.
    )


class ContactRole(StrEnum):
    """The RDAP entity role a ``Contact`` serves.

    Subset of RFC 7483 section 10.2.4. The OA-meaningful roles only - we
    intentionally do not project unknown / non-standard role values
    onto an ``OTHER`` bucket; the parser drops entities whose role
    is outside this set rather than smuggle unfamiliar prose
    through. Add a member here when a new role earns its keep.
    """

    REGISTRANT = "registrant"  # who registered the resource
    ABUSE = "abuse"  # preferred contact for abuse reports
    ADMIN = "admin"  # administrative contact
    TECHNICAL = "technical"  # technical / operational contact
    NOC = "noc"  # network operations center


class Contact(BaseModel):
    """A point-of-contact entity from an RDAP entity record.

    Captures the vCard fields RDAP entities surface (RFC 7095): display
    name, email, phone, plus the entity's RDAP role from the
    ``ContactRole`` catalogue. One ``Contact`` per RDAP entity the
    parser recognises.

    Maps to amass's hanging ``SimpleProperty`` group on the
    ``RIROrganization`` asset when amass lands (#45) - one Contact is
    a clustered set of contact properties for a given role.

    All vCard fields are optional - RIRs vary in which slots they
    expose. A Contact carrying only ``role`` + ``email`` is useful
    (the abuse channel); ``role`` + ``name`` alone is less useful but
    a valid record.
    """

    role: ContactRole
    email: Email | None = None
    # Tool-captured from RDAP's vCard ``fn`` field. Defence: bounded
    # length at the model boundary - RIRs emit short, trustworthy
    # strings, so a max_length cap is the right level of defence
    # without further escaping (the field flows into reports and is
    # not re-issued to LLMs as instruction context).
    name: str | None = Field(default=None, max_length=255)
    # Tool-captured from RDAP's vCard ``tel`` field. Same defence:
    # bounded length, no shape constraint (international phone formats
    # vary; the OA reads this as opaque contact metadata).
    phone: str | None = Field(default=None, max_length=64)


class RdapRecord(BaseModel):
    """Structured-registrant record from an RDAP (RFC 7483) lookup.

    Maps to amass's ``RIROrganization`` asset - the entity an IP /
    netblock / ASN is registered to. Where ``AsnRecord`` carries the
    Cymru flat row (ASN + netblock + AS-name + country in one string),
    ``RdapRecord`` carries the RDAP-structured equivalent: each
    registrant property is a separate field, abuse contact is its own
    typed entry, registration / last-change events are typed datetimes
    rather than strings.

    Both lookups can run for the same IP - they answer different
    questions: ``AsnRecord`` asks "what ASN announces this IP" (BGP-
    routing layer), ``RdapRecord`` asks "what RIR entity owns this
    address space" (registration layer). The two together populate the
    full ``IPAddress -> Netblock -> AutonomousSystem -> RIROrganization``
    OAM chain.

    All optional fields default to None - RIRs vary in which entities
    they expose (some omit abuse contacts, some omit events), and the
    record is useful with whatever subset returns. ``source_url`` is
    the audit trail: the RDAP endpoint we actually queried, so a future
    re-lookup or a triage cross-check has a deterministic starting
    point.
    """

    query: str = Field(
        max_length=64,
        # The IP address (e.g. "8.8.8.8") or AS handle (e.g. "AS15169")
        # we sent to RDAP. Captured as-sent so the record carries its
        # own provenance; the validator on the typed lookup-fn entry
        # points already rejected mis-shaped values upstream.
    )
    handle: str | None = Field(
        default=None,
        max_length=128,
        # The RIR-assigned handle for this resource (e.g. "NET-8-8-8-0-1"
        # for an ARIN network, "AS15169" for an ARIN autnum). Stable
        # across re-lookups; the natural join key into the RIROrganization
        # asset once amass lands.
    )
    rir: str | None = Field(
        default=None,
        max_length=16,
        # Which Regional Internet Registry served this record:
        # ARIN / RIPE / APNIC / LACNIC / AFRINIC. Derived from the
        # bootstrap registry hop, not from the RDAP payload itself.
    )
    registrant_organisation: str | None = Field(
        default=None,
        max_length=255,
        # The registrant entity's display name from its vCard ``fn``
        # field. Tool-captured: RIRs validate this at registration time,
        # but length-cap as the boundary guard against an RDAP server
        # returning an outsize string.
    )
    abuse_email: str | None = Field(
        default=None,
        max_length=255,
        # Preferred contact email from the entity with role "abuse" in
        # the RDAP response. The natural target for a disclosure email
        # that needs to reach the asset owner directly rather than
        # through the bug bounty platform.
    )
    registered_at: datetime | None = Field(
        default=None,
        # Earliest "registration" event from the RDAP events array. When
        # the resource was first allocated by the RIR. None when the
        # RIR did not surface a registration event.
    )
    last_changed_at: datetime | None = Field(
        default=None,
        # Latest "last changed" event from the RDAP events array. Useful
        # signal for "registrant may have changed since the prior recon".
    )
    source_url: str | None = Field(
        default=None,
        max_length=512,
        # The RDAP endpoint URL we queried. Audit trail: a triage cross-
        # check or re-lookup hits the same authoritative endpoint
        # without re-running the bootstrap-registry hop.
    )
    contacts: list[Contact] = Field(
        default_factory=list,
        # Structured per-role contact records walked out of the RDAP
        # ``entities`` array - registrant, abuse, admin, technical, NOC.
        # The flat ``abuse_email`` / ``registrant_organisation`` fields
        # above are the convenience-access shortcuts for the two roles
        # the OA reads most often; ``contacts`` carries the full set
        # for downstream consumers that want the richer surface (e.g.
        # a disclosure email composer that wants every email it can
        # reach).
    )


__all__ = [
    "AsnRecord",
    "AutonomousSystem",
    "Contact",
    "ContactRole",
    "IPAddress",
    "Netblock",
    "RdapRecord",
]
