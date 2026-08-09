"""
models.primitives.email - the ``Email`` typed-string primitive.

An RFC 5321 / 5322 address validated via the ``email_validator`` library
(the same one Pydantic's ``EmailStr`` uses under the hood).
"""

from __future__ import annotations

from typing import Annotated

from pydantic import AfterValidator

# ``Email`` - typed string for an RFC 5321 / 5322 email address.
# Validates via the ``email_validator`` library (the same one Pydantic's
# ``EmailStr`` uses under the hood). Runtime stays ``str`` to match the
# ``FQDN`` / ``HttpUrl`` / ``IpAddr`` convention - consumers that do
# ``.split("@")`` / ``.lower()`` / dict-key work without an audit.
#
# Used by ``models.network.Contact.email`` for the structured-registrant
# entries pulled from RDAP (abuse / registrant / admin / technical
# vCards). Capped at 254 chars per RFC 5321 section 4.5.3.1.1 by the validator;
# the cap is enforced inside ``validate_email`` rather than as a
# separate Field constraint so callers cannot bypass it via direct
# construction.


def _validate_email(value: str) -> str:
    """Validate that ``value`` is a parseable email address.

    Delegates to ``email_validator.validate_email`` with
    ``check_deliverability=False`` - we want syntactic validation, not
    an MX-lookup that fires a DNS query inside every model construction.
    Returns the normalised form (case-folded domain, Unicode
    normalisation) so equality holds across input variants
    (``Abuse@Example.COM`` and ``abuse@example.com`` both resolve to the
    same canonical string).
    """
    if not isinstance(value, str):  # pragma: no cover - Pydantic enforces str upstream
        raise ValueError(f"Email must be a string, got {type(value).__name__}")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("Email cannot be empty")

    from email_validator import EmailNotValidError, validate_email

    try:
        result = validate_email(cleaned, check_deliverability=False)
    except EmailNotValidError as exc:
        raise ValueError(f"invalid email {value!r}: {exc}") from exc
    return result.normalized


Email = Annotated[str, AfterValidator(_validate_email)]
