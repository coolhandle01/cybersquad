"""Network path tracing to surface origin IPs behind CDNs and WAFs."""

from __future__ import annotations

import logging
import re
import shutil

from config import config
from tools._helpers import _run

logger = logging.getLogger(__name__)

# Matches dotted-decimal IPv4 addresses
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Matches lines that represent a hop (start with optional whitespace + hop number).
# Filters out the traceroute header line ("traceroute to host (IP), ...").
_HOP_LINE_RE = re.compile(r"^\s*\d+")

# Private / RFC1918 / loopback ranges we filter out of hop lists
_PRIVATE_PREFIXES = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "127.",
    "169.254.",
)


def _is_public(ip: str) -> bool:
    return not any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _parse_hops(output: str) -> list[str]:
    """Extract ordered, deduplicated public IPv4 hop addresses from traceroute output.

    Only processes lines that start with a hop number to skip the header line
    (e.g. "traceroute to host (IP)...") that would otherwise inject the destination
    IP at position 0, ahead of the actual first hop.
    """
    seen: set[str] = set()
    hops: list[str] = []
    for line in output.splitlines():
        if not _HOP_LINE_RE.match(line):
            continue
        for ip in _IPV4_RE.findall(line):
            if _is_public(ip) and ip not in seen:
                seen.add(ip)
                hops.append(ip)
    return hops


def run_traceroute(hostnames: list[str], max_hops: int = 20) -> dict[str, list[str]]:
    """Trace the network path to each hostname and return public hop IP lists.

    Uses tracepath (no root required) with fallback to traceroute. Returns an
    empty list for any host that times out or where the binary is unavailable.
    Result is stored in AttackGraph.network_hops so all downstream agents can
    reason about CDN/WAF bypass opportunities (e.g. origin IP directly reachable).

    Skips entirely when ``config.scan.traceroute_enabled`` is False - ICMP
    from the operator IP is the OA's loudest tool against the target, so
    STEALTH posture trades the CDN-bypass signal for a quieter footprint.
    Gated here rather than at the call site so any caller (the sweep,
    a future per-host pivot tool, a one-off agent invocation) inherits
    the stealth contract.
    """
    if not config.scan.traceroute_enabled:
        logger.debug("traceroute disabled by scan_mode posture; skipping")
        return {}

    binary = shutil.which("tracepath") or shutil.which("traceroute")
    if not binary:
        logger.debug("No tracepath or traceroute binary found; skipping network path trace")
        return {}

    results: dict[str, list[str]] = {}
    for host in hostnames:
        try:
            if "tracepath" in binary:
                cmd = [binary, "-n", "-m", str(max_hops), host]
            else:
                cmd = [binary, "-n", "-m", str(max_hops), "-w", "2", host]
            result = _run(cmd, timeout=60)
            results[host] = _parse_hops(result.stdout)
            logger.debug("traceroute to %s: %d public hops", host, len(results[host]))
        except Exception as exc:
            logger.debug("traceroute failed for %s: %s", host, exc)
            results[host] = []

    return results
