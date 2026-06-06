"""Subdomain enumeration via subfinder."""

from __future__ import annotations

import logging

from config import config
from tools._helpers import _require_binary, _run

logger = logging.getLogger(__name__)


def enumerate_subdomains(domain: str) -> list[str]:
    """Use subfinder to enumerate subdomains. Returns deduplicated hostnames.

    Rate / thread caps and the ``-active`` flag (which switches on live
    DNS resolution of each candidate) all live on ``config.scan`` and
    follow the operator's stealth dial via ``ScanConfig.__post_init__``.
    STEALTH leaves ``-active`` off so the lookup stays passive against
    third-party sources only; NORMAL / RAID enable it for a fuller surface.
    """
    subfinder = _require_binary("subfinder")
    argv = [
        subfinder,
        "-d",
        domain,
        "-silent",
        "-o",
        "/dev/stdout",
        "-rl",
        str(config.scan.subfinder_rate_limit),
        "-t",
        str(config.scan.subfinder_threads),
    ]
    if config.scan.subfinder_active:
        argv.append("-active")
    result = _run(argv, timeout=180)
    subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    logger.info("subfinder found %d subdomains for %s", len(subdomains), domain)
    return list(dict.fromkeys(subdomains))[: config.recon.max_subdomains]
