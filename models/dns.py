"""
models/dns.py - typed shapes for DNS-derived recon signals.

The DNS-layer probes (currently dnsx-based takeover detection +
reverse-lookup PTR) return typed records consumers read against;
the data live in ``tools/recon/dnsx.py``, the contract lives here.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from models.primitives import FQDN, IpAddr


class TakeoverCandidate(BaseModel):
    """A subdomain flagged as a potential takeover target.

    ``reason`` is one of:
      - ``cname_to_vulnerable_provider``: CNAME points to a service in the
        ``_TAKEOVER_FINGERPRINTS`` catalogue. Probe the host with HTTP and
        look for the service-specific "not found" body.
      - ``dangling_cname``: CNAME exists but the chain does not resolve to
        any A records. The CNAME target may have been deprovisioned.
    """

    hostname: FQDN
    cname: str
    reason: str
    service: str | None = None


class PtrRecord(BaseModel):
    """One IP's reverse-DNS lookup result.

    PTR is the inverse of A: where A maps a hostname to an IP, PTR
    maps an IP back to whatever name(s) the in-addr.arpa zone publishes
    for it. Useful for IP-rooted enrichment: an IP whose PTR resolves
    to ``ec2-203-0-113-7.compute-1.amazonaws.com`` tells you the host
    runs on EC2 even when the front-door FQDN is CDN-fronted; a PTR
    to ``mail.example.com`` from an IP not in the recon's subdomain
    list reveals a forgotten asset.

    Multiple PTR answers per IP are uncommon but legal - the resolver
    returns whatever names the in-addr.arpa zone publishes.
    """

    ip: IpAddr
    hostnames: list[FQDN] = Field(default_factory=list)


__all__ = ["PtrRecord", "TakeoverCandidate"]
