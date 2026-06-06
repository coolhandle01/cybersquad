"""
models.asset.org - the OAM ``Organization`` asset.

An organisation observed on the surface - a registrant, a service provider,
a vendor. Carries the firmographic detail OAM tracks; the contacts / people
that belong to it are separate assets joined by relations.

OAM asset:
<https://owasp-amass.github.io/docs/open_asset_model/assets/organization/>
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class Organization(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``Organization`` asset.

    Mirrors amass field for field (OAM json tag in parentheses). The
    free-text fields are tool- / registry-captured: length-capped at the
    boundary, read as data, never re-issued to an LLM as instruction context.
    """

    name: str = Field(min_length=1, max_length=255)  # name
    org_id: str = Field(default="", max_length=128)  # unique_id
    legal_name: str = Field(default="", max_length=255)  # legal_name
    founding_date: str = Field(default="", max_length=64)  # founding_date
    jurisdiction: str = Field(default="", max_length=128)  # jurisdiction
    registration_id: str = Field(default="", max_length=128)  # registration_id
    industry: str = Field(default="", max_length=128)  # industry
    target_markets: list[str] = Field(default_factory=list)  # target_markets
    active: bool = False  # active
    non_profit: bool = False  # non_profit
    headcount: int = Field(default=0, ge=0)  # headcount
