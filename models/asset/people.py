"""
models.asset.people - the OAM ``Person`` asset.

A natural person observed on the surface - a registrant / administrative /
technical contact a WHOIS or RDAP record names. Their email / phone /
location are separate assets joined by relations.

OAM asset:
<https://owasp-amass.github.io/docs/open_asset_model/assets/person/>
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class Person(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``Person`` asset.

    Mirrors amass field for field (OAM json tag in parentheses). The name
    fields are tool- / registry-captured: length-capped at the boundary,
    read as data, never re-issued to an LLM as instruction context.
    """

    full_name: str = Field(min_length=1, max_length=255)  # full_name
    person_id: str = Field(default="", max_length=128)  # unique_id
    first_name: str = Field(default="", max_length=128)  # first_name
    middle_name: str = Field(default="", max_length=128)  # middle_name
    family_name: str = Field(default="", max_length=128)  # family_name
    birth_date: str = Field(default="", max_length=64)  # birth_date
    gender: str = Field(default="", max_length=32)  # gender
