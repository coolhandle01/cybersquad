"""Unauthenticated Elasticsearch check."""

from __future__ import annotations

import logging

from models import RawFinding, Severity
from models.service import Service
from tools import http
from tools.pentest.service import service

logger = logging.getLogger(__name__)

PORT = 9200


@service(Service.elasticsearch)
def check_elasticsearch(host: str) -> list[RawFinding]:
    """Return a CRITICAL finding if Elasticsearch on port 9200 responds without auth."""
    url = f"http://{host}:{PORT}/_cluster/health"
    try:
        resp = http.get(url, timeout=5, allow_redirects=False)  # nosemgrep
        if resp.status_code == 200 and "cluster_name" in resp.text:
            return [
                RawFinding(
                    title=f"Unauthenticated Elasticsearch - {host}",
                    vuln_class="ExposedService",
                    target=url,
                    evidence=(
                        f"Elasticsearch responded without authentication.\n"
                        f"Response: {resp.text[:300]}"
                    ),
                    tool="elasticsearch_check",
                    severity_hint=Severity.CRITICAL,
                )
            ]
    except Exception as exc:
        logger.debug("Elasticsearch check failed for %s: %s", host, exc)
    return []
