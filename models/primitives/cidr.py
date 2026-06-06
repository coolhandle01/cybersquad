"""
models.primitives.cidr - the ``Cidr`` typed-string primitive.

An IPv4 / IPv6 network prefix validated via stdlib ``ipaddress.ip_network``;
the netblock counterpart to ``ip_addr.IpAddr``.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import AfterValidator

# ``Cidr`` - typed string for an IPv4 / IPv6 network prefix, the netblock
# counterpart to ``IpAddr``. Validates via stdlib ``ipaddress.ip_network``
# (``strict=False`` so a host-bit-set value like ``8.8.8.8/24`` normalises to
# its network ``8.8.8.0/24`` rather than rejecting). Runtime stays ``str`` to
# match the ``FQDN`` / ``HttpUrl`` / ``IpAddr`` convention. Used by the OAM
# ``Netblock`` / ``IPNetRecord`` assets.


def _validate_cidr(value: str) -> str:
    """Validate that ``value`` is a parseable IPv4 / IPv6 CIDR prefix.

    Delegates to stdlib ``ipaddress.ip_network`` with ``strict=False`` (so a
    host-bit-set prefix normalises to its network rather than rejecting) and
    returns the canonical form so equality holds across input variants.
    Rejects a bare address (no prefix length - that is an ``IpAddr``),
    hostnames, and garbage.
    """
    import ipaddress

    if not isinstance(value, str):  # pragma: no cover - Pydantic enforces str upstream
        raise ValueError(f"CIDR must be a string, got {type(value).__name__}")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("CIDR cannot be empty")
    if "/" not in cleaned:
        raise ValueError(f"CIDR must include a prefix length (got a bare address?): {value!r}")
    try:
        parsed = ipaddress.ip_network(cleaned, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR {value!r}: {exc}") from exc
    return str(parsed)


Cidr = Annotated[str, AfterValidator(_validate_cidr)]
