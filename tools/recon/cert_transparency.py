"""Subdomain discovery via crt.sh certificate transparency logs."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def cert_transparency(domain: str) -> list[str]:
    """Query crt.sh to discover subdomains not found by active enumeration."""
    from tools import http

    resp = http.get(
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        timeout=30,
    )
    resp.raise_for_status()
    names: list[str] = []
    for entry in resp.json():
        for name in entry.get("name_value", "").splitlines():
            cleaned = name.strip().lstrip("*.")
            if cleaned and (cleaned == domain or cleaned.endswith("." + domain)):
                names.append(cleaned)
    logger.info("crt.sh found %d names for %s", len(names), domain)
    return list(dict.fromkeys(names))
