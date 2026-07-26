"""Historical URL discovery via waybackurls and the Wayback Machine."""

from __future__ import annotations

import logging

from tools._helpers import _require_binary, _run

logger = logging.getLogger(__name__)


def historical_urls(domain: str) -> list[str]:
    """Use waybackurls to discover historical endpoints from the Wayback Machine."""
    binary = _require_binary("waybackurls")
    result = _run([binary, domain], timeout=180)
    urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    logger.info("waybackurls found %d historical URLs for %s", len(urls), domain)
    return urls
