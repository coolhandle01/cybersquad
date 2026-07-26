"""
models.primitives.ip_type - the ``IPType`` IP-family discriminator enum.

The OAM ``IPv4`` / ``IPv6`` ``type`` stamped on ``IPAddress`` / ``Netblock``
assets. Distinct from the address literal (``ip_addr.IpAddr``).
"""

from __future__ import annotations

from enum import StrEnum


class IPType(StrEnum):
    """The OAM IP-family ``type`` stamped on ``IPAddress`` / ``Netblock``
    assets - ``IPv4`` or ``IPv6``.

    Distinct from ``IPNetRecord.type``, which is the RDAP *allocation* type
    (e.g. "ALLOCATED", "ASSIGNED PORTABLE") and stays a free string.
    """

    IPV4 = "IPv4"
    IPV6 = "IPv6"
