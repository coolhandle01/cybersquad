"""
models.primitives.ip_addr - the ``IpAddr`` typed-string primitive.

An IPv4 / IPv6 address literal validated via stdlib ``ipaddress.ip_address``;
the netblock counterpart is ``cidr.Cidr``.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import AfterValidator

# ``IpAddr`` - typed string for an IPv4 or IPv6 address. Validates
# via stdlib ``ipaddress.ip_address`` (handles both versions; rejects
# malformed strings, CIDR notation, hostnames). Keeps the runtime as
# ``str`` to match the ``FQDN`` / ``HttpUrl`` convention - every
# consumer that does ``f"https://{ip}"`` / ``ip.startswith(...)`` /
# dict-key works without coercion. The ASN-lookup (`tools/recon/asn.py`
# via Team Cymru) and the future amass ``IPAddress`` asset type both
# read this primitive at the boundary.
#
# Deliberately separate from `FQDN` even though both end up in
# DNS-resolution paths: the validators are mutually exclusive (a string
# is either a valid IP literal or a valid hostname, never both), so
# union-typing them would let one slip past the wrong validator. Two
# primitives, two strict gates.


def _validate_ip_address(value: str) -> str:
    """Validate that ``value`` is a parseable IPv4 or IPv6 address literal.

    Delegates to stdlib ``ipaddress.ip_address``. Rejects:

    * CIDR notation (``1.2.3.0/24``) - that is a netblock, not an IP
    * FQDNs (``example.com``) - validator-distinct from ``FQDN``
    * IPv6 zone identifiers (``fe80::1%eth0``) - link-local scope IDs
      are not stable across hosts and shouldn't appear in recon JSON
    * Empty / whitespace-only input

    Returns the normalised form from ``ipaddress.ip_address`` so equality
    holds across input variations (``::1`` and ``0:0:0:0:0:0:0:1`` both
    resolve to the same canonical string).
    """
    import ipaddress

    if not isinstance(value, str):  # pragma: no cover - Pydantic enforces str upstream
        raise ValueError(f"IP address must be a string, got {type(value).__name__}")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("IP address cannot be empty")
    if "/" in cleaned:
        raise ValueError(f"IP address must not include CIDR notation: {value!r}")
    if "%" in cleaned:
        raise ValueError(f"IP address must not include IPv6 zone identifier: {value!r}")
    try:
        parsed = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid IP address {value!r}: {exc}") from exc
    return str(parsed)


IpAddr = Annotated[str, AfterValidator(_validate_ip_address)]
