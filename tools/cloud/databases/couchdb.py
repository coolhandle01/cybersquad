"""Unauthenticated CouchDB check."""

from __future__ import annotations

import logging

from models import RawFinding, Severity
from models.service import Service
from tools import http
from tools.pentest.service import service

logger = logging.getLogger(__name__)

PORT = 5984


@service(Service.couchdb)
def check_couchdb(host: str) -> list[RawFinding]:
    """Return a CRITICAL finding if CouchDB on port 5984 lists databases without auth."""
    url = f"http://{host}:{PORT}/_all_dbs"
    try:
        resp = http.get(url, timeout=5, allow_redirects=False)  # nosemgrep
        if resp.status_code == 200 and "[" in resp.text:
            return [
                RawFinding(
                    title=f"Unauthenticated CouchDB - {host}",
                    vuln_class="ExposedService",
                    target=url,
                    evidence=(
                        f"CouchDB listed all databases without authentication.\n"
                        f"Response: {resp.text[:300]}"
                    ),
                    tool="couchdb_check",
                    severity_hint=Severity.CRITICAL,
                )
            ]
    except Exception as exc:
        logger.debug("CouchDB check failed for %s: %s", host, exc)
    return []
