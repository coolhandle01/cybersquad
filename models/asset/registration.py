"""
models.asset.registration - the OAM WHOIS / RDAP registration records.

The registrant-side records a WHOIS / RDAP lookup returns for a domain
(``DomainRecord``), an IP network (``IPNetRecord``), or an autonomous system
(``AutnumRecord``). Each is the raw registry record; the registrant
``Organization`` / ``ContactRecord`` it points at are separate assets joined
by relations.

OAM assets:
* ``DomainRecord`` <https://owasp-amass.github.io/docs/open_asset_model/assets/domain_record/>
* ``IPNetRecord`` <https://owasp-amass.github.io/docs/open_asset_model/assets/ipnet_record/>
* ``AutnumRecord`` <https://owasp-amass.github.io/docs/open_asset_model/assets/autnum_record/>
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from models.primitives import Cidr


class DomainRecord(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``DomainRecord`` asset.

    A domain's WHOIS record. Dates stay verbatim strings (registrars vary).
    Mirrors amass field for field (OAM json tag in parentheses).
    """

    domain: str = Field(min_length=1, max_length=255)  # domain
    # Tool-captured raw WHOIS text. Defence: boundary length cap; human /
    # audit-facing, never re-issued to an LLM as instruction context.
    raw: str = Field(default="", max_length=8000)  # raw
    record_id: str = Field(default="", max_length=128)  # id
    punycode: str = Field(default="", max_length=255)  # punycode
    name: str = Field(default="", max_length=255)  # name
    extension: str = Field(default="", max_length=64)  # extension (the TLD)
    whois_server: str = Field(default="", max_length=255)  # whois_server
    created_date: str = Field(default="", max_length=64)  # created_date (verbatim)
    updated_date: str = Field(default="", max_length=64)  # updated_date (verbatim)
    expiration_date: str = Field(default="", max_length=64)  # expiration_date (verbatim)
    status: list[str] = Field(default_factory=list)  # status (EPP status codes)
    dnssec: bool = False  # dnssec


class IPNetRecord(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``IPNetRecord`` asset.

    The RDAP record for an IP network (the registrant of an address block).
    Mirrors amass field for field (OAM json tag in parentheses); ``cidr`` /
    ``start_address`` / ``end_address`` are kept as strings (amass uses
    ``netip`` types; cybersquad keeps the registry text verbatim).
    """

    cidr: Cidr  # cidr - validated IPv4/IPv6 network prefix
    handle: str = Field(default="", max_length=128)  # handle
    # Tool-captured raw RDAP text; boundary length cap, human / audit-facing.
    raw: str = Field(default="", max_length=8000)  # raw
    start_address: str = Field(default="", max_length=64)  # start_address
    end_address: str = Field(default="", max_length=64)  # end_address
    type: str = Field(default="", max_length=64)  # type
    name: str = Field(default="", max_length=255)  # name
    method: str = Field(default="", max_length=64)  # method
    country: str = Field(default="", max_length=8)  # country
    parent_handle: str = Field(default="", max_length=128)  # parent_handle
    whois_server: str = Field(default="", max_length=255)  # whois_server
    created_date: str = Field(default="", max_length=64)  # created_date
    updated_date: str = Field(default="", max_length=64)  # updated_date
    status: list[str] = Field(default_factory=list)  # status


class AutnumRecord(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``AutnumRecord`` asset.

    The RDAP record for an autonomous system (the registrant of an ASN).
    Mirrors amass field for field (OAM json tag in parentheses).
    """

    number: int = Field(ge=0, le=4_294_967_295)  # number (32-bit ASN per RFC 6793)
    handle: str = Field(default="", max_length=128)  # handle
    name: str = Field(default="", max_length=255)  # name
    # Tool-captured raw RDAP text; boundary length cap, human / audit-facing.
    raw: str = Field(default="", max_length=8000)  # raw
    whois_server: str = Field(default="", max_length=255)  # whois_server
    created_date: str = Field(default="", max_length=64)  # created_date
    updated_date: str = Field(default="", max_length=64)  # updated_date
    status: list[str] = Field(default_factory=list)  # status
