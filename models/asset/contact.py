"""
models.asset.contact - the OAM ``ContactRecord`` asset and its detail shapes.

A ``ContactRecord`` is the OAM join node a WHOIS / RDAP record points at; the
``Person`` / ``Organization`` / ``Phone`` / ``Location`` / email
(``Identifier``) it gathers hang off it by relations. ``Phone`` and
``Location`` are the contact-detail assets.

OAM assets:
* ``ContactRecord`` <https://owasp-amass.github.io/docs/open_asset_model/assets/contact_record/>
* ``Location`` <https://owasp-amass.github.io/docs/open_asset_model/assets/location/>
* ``Phone`` <https://owasp-amass.github.io/docs/open_asset_model/assets/phone/>
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ContactRecord(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``ContactRecord`` asset.

    The bare join node - just when it was discovered. The actual contact
    (person / org / phone / location / email) attaches by relations.
    """

    discovered_at: str = Field(default="", max_length=64)  # discovered_at


class Location(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``Location`` asset.

    A postal address. Mirrors amass field for field (OAM json tag in
    parentheses). Registry-captured free text: length-capped at the boundary.
    """

    address: str = Field(default="", max_length=512)  # address
    building: str = Field(default="", max_length=128)  # building
    building_number: str = Field(default="", max_length=32)  # building_number
    street_name: str = Field(default="", max_length=255)  # street_name
    unit: str = Field(default="", max_length=64)  # unit
    po_box: str = Field(default="", max_length=64)  # po_box
    city: str = Field(default="", max_length=128)  # city
    locality: str = Field(default="", max_length=128)  # locality
    province: str = Field(default="", max_length=128)  # province
    country: str = Field(default="", max_length=64)  # country
    postal_code: str = Field(default="", max_length=32)  # postal_code
    gln: int = Field(default=0, ge=0)  # gln (Global Location Number)


class Phone(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``Phone`` asset.

    A telephone number. Mirrors amass field for field (OAM json tag in
    parentheses). Registry-captured free text: length-capped at the boundary.
    """

    raw: str = Field(default="", max_length=64)  # raw
    e164: str = Field(default="", max_length=32)  # e164
    type: str = Field(default="", max_length=32)  # type
    country_abbrev: str = Field(default="", max_length=8)  # country_abbrev
    country_code: int = Field(default=0, ge=0)  # country_code
    ext: str = Field(default="", max_length=16)  # ext
