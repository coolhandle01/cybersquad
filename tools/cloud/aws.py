"""AWS S3 bucket misconfiguration checks.

``check_s3_buckets`` probes each supplied S3 hostname for public
listing (HTTP 200 with ``<ListBucketResult``) or bare 200 (publicly
accessible but no listing). FQDNs come from the wrapper's
scope-filtered agent pick - typically ``*.s3.*.amazonaws.com``
entries the OSINT Analyst surfaced in ``recon.subdomains``.
"""

from __future__ import annotations

import logging

from models import RawFinding, Severity
from tools import http

logger = logging.getLogger(__name__)


def check_s3_buckets(hostnames: list[str]) -> list[RawFinding]:
    """
    Check each supplied S3 hostname for public listing or accessibility.

    The agent picks hostnames the OSINT Analyst surfaced in
    ``recon.subdomains`` (DNS, certificate transparency, historical
    URLs) that match the ``*.s3.*.amazonaws.com`` pattern. No
    bucket-name guessing - we only probe assets the programme has
    actually exposed and OSINT has actually discovered.
    """
    findings: list[RawFinding] = []

    for hostname in hostnames:
        url = f"https://{hostname}/"
        try:
            resp = http.get(url, timeout=10, allow_redirects=False)  # nosemgrep
        except Exception as exc:
            logger.debug("S3 check failed for %s: %s", hostname, exc)
            continue

        if resp.status_code == 200 and "<ListBucketResult" in resp.text:
            findings.append(
                RawFinding(
                    title=f"S3 Bucket Publicly Listable - {hostname}",
                    vuln_class="CloudMisconfiguration",
                    target=url,
                    evidence=(
                        f"Bucket listing returned HTTP 200.\nResponse excerpt:\n{resp.text[:500]}"
                    ),
                    tool="s3_bucket_check",
                    severity_hint=Severity.HIGH,
                )
            )
        elif resp.status_code == 200:
            findings.append(
                RawFinding(
                    title=f"S3 Bucket Publicly Accessible - {hostname}",
                    vuln_class="CloudMisconfiguration",
                    target=url,
                    evidence="Bucket URL returned HTTP 200 without listing - verify manually.",
                    tool="s3_bucket_check",
                    severity_hint=Severity.MEDIUM,
                )
            )

    logger.info("S3 check found %d findings", len(findings))
    return findings
