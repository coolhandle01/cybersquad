"""Azure Blob Storage misconfiguration checks.

``check_azure_blob_containers`` probes each supplied Azure Blob
hostname for publicly listable containers under the canonical
Azure-pattern names (``public``, ``assets``, ``static``, ...). The
container-name list is the well-known Azure-pattern set, equivalent
to the canonical ``/admin`` paths probed against discovered web
origins.

``check_azure_sas_tokens`` scans each supplied endpoint URL for
embedded SAS-token query parameters (sv / se / sig / sr / sp); static
URL inspection, no HTTP fires.
"""

from __future__ import annotations

import logging
import re

from models import Endpoint, RawFinding, Severity
from tools import http

logger = logging.getLogger(__name__)

_CONTAINER_NAMES = [
    "public",
    "assets",
    "static",
    "uploads",
    "media",
    "files",
    "images",
    "data",
    "$root",
]

# Azure SAS token query parameters
_SAS_RE = re.compile(r"[?&](sv|se|sig|sr|sp)=", re.I)


def check_azure_blob_containers(hostnames: list[str]) -> list[RawFinding]:
    """
    Check each supplied Azure Blob hostname for publicly listable
    containers under the canonical Azure-pattern names (``public``,
    ``assets``, ``static``, etc.).

    The agent picks hostnames the OSINT Analyst surfaced in
    ``recon.subdomains`` that match the ``*.blob.core.windows.net``
    pattern. No account-name guessing - we only probe assets the
    programme has actually exposed and OSINT has actually discovered;
    the container-name list is the well-known Azure-pattern set
    (equivalent to the canonical ``/admin`` paths in
    ``check_admin_panels``).
    """
    findings: list[RawFinding] = []

    for hostname in hostnames:
        for container in _CONTAINER_NAMES:
            url = f"https://{hostname}/{container}?restype=container&comp=list"
            try:
                resp = http.get(url, timeout=10, allow_redirects=False)  # nosemgrep
            except Exception as exc:
                logger.debug("Azure check failed for %s/%s: %s", hostname, container, exc)
                continue

            if resp.status_code == 200 and "<EnumerationResults" in resp.text:
                findings.append(
                    RawFinding(
                        title=f"Azure Blob Container Publicly Listed - {hostname}/{container}",
                        vuln_class="CloudMisconfiguration",
                        target=url,
                        evidence=(
                            f"Container listing returned HTTP 200.\n"
                            f"Response excerpt:\n{resp.text[:500]}"
                        ),
                        tool="azure_blob_container_check",
                        severity_hint=Severity.HIGH,
                    )
                )

    logger.info("Azure blob container check found %d findings", len(findings))
    return findings


def check_azure_sas_tokens(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Scan each supplied endpoint URL for embedded Azure SAS-token query
    parameters (``sv`` / ``se`` / ``sig`` / ``sr`` / ``sp``). Static
    URL inspection - no HTTP requests. SAS tokens embedded in URLs are
    logged by intermediate proxies and browser history; surfacing them
    is the finding.
    """
    findings: list[RawFinding] = []

    for ep in endpoints:
        if _SAS_RE.search(ep.url):
            findings.append(
                RawFinding(
                    title=f"Azure SAS Token in URL - {ep.url}",
                    vuln_class="CloudMisconfiguration",
                    target=ep.url,
                    evidence=(
                        "SAS token query parameters (sv/se/sig/sr/sp) detected in URL. "
                        "Tokens embedded in URLs are logged by proxies and browsers."
                    ),
                    tool="azure_sas_token_check",
                    severity_hint=Severity.HIGH,
                )
            )

    logger.info("Azure SAS token check found %d findings", len(findings))
    return findings
