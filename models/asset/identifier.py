"""
models.asset.identifier - the OAM ``Identifier`` asset.

A typed external identifier - an email address, a registry handle, an account
id - the ``id_type`` distinguishing which. cybersquad uses it for the RDAP
abuse / registrant email a ``ContactRecord`` points at (``id_type="email"``).

OAM asset:
<https://owasp-amass.github.io/docs/open_asset_model/assets/identifier/>
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class Identifier(BaseModel):
    """The cybersquad shape that maps to amass's OAM ``Identifier`` asset.

    Mirrors amass field for field (OAM json tag in parentheses): ``id`` is the
    value (e.g. the email address), ``id_type`` the scheme ("email",
    "handle", ...). Registry-captured: length-capped at the boundary.
    """

    id: str = Field(min_length=1, max_length=255)  # id (the value, e.g. an email)
    id_type: str = Field(default="", max_length=32)  # id_type ("email" / "handle")
    unique_id: str = Field(default="", max_length=128)  # unique_id
    creation_date: str = Field(default="", max_length=64)  # creation_date
    update_date: str = Field(default="", max_length=64)  # update_date
    expiration_date: str = Field(default="", max_length=64)  # expiration_date
    status: str = Field(default="", max_length=64)  # status
