"""
TLS and DNS security checks.

TLS: wraps the testssl.sh CLI binary to probe HTTPS endpoints for weak
ciphers, outdated protocols (TLS 1.0/1.1), missing HSTS, expired or
misconfigured certificates, and known CVEs (Heartbleed, POODLE, etc.).

DNS: uses dnspython to check email authentication records (SPF, DMARC)
for each discovered domain. Missing or unenforced policies are common
HackerOne findings and require no binary dependency.

Binary required: testssl.sh (or testssl) for TLS checks.
Python dependency: dnspython (for DNS checks).
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import shutil
import tempfile
from urllib.parse import urlparse

import dns.exception
import dns.resolver

from config import config
from models import Endpoint, RawFinding, Severity
from tools._helpers import _run

logger = logging.getLogger(__name__)

# testssl.sh severity labels that represent real findings
_TESTSSL_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    # testssl uses "NOT ok" for some checks that don't fit a numeric severity
    "NOT ok": Severity.MEDIUM,
    "WARN": Severity.LOW,
}

# testssl check IDs that are informational and should not become findings
_TESTSSL_SKIP_IDS = {
    "service",
    "HTTP_clock_skew",
    "cert_chain_of_trust",
    "protocol_support_offered",
}


def _root_domain(hostname: str) -> str:
    """Strip subdomains to the organisational domain (last two labels).

    Approximate - ignores multi-part ccTLDs like .co.uk, but good enough
    for SPF/DMARC lookups where false negatives are preferable to noise.
    """
    parts = hostname.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def _get_spf(domain: str) -> str | None:
    """Return the first SPF TXT record for domain, or None if absent."""
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            for txt_bytes in rdata.strings:
                txt: str = txt_bytes.decode("utf-8", errors="replace")
                if txt.startswith("v=spf1"):
                    return txt
    except dns.exception.DNSException:
        pass
    return None


def _get_dmarc(domain: str) -> str | None:
    """Return the DMARC TXT record for _dmarc.<domain>, or None if absent."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            for txt_bytes in rdata.strings:
                txt: str = txt_bytes.decode("utf-8", errors="replace")
                if txt.startswith("v=DMARC1"):
                    return txt
    except dns.exception.DNSException:
        pass
    return None


def check_tls(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Run testssl.sh against live HTTPS endpoints and return findings.

    One run per unique hostname; capped at config.scan.tls_max_targets.
    If testssl.sh is not installed, logs a warning and returns [].

    Skips entirely when ``config.scan.tls_enabled`` is False. testssl
    fires hundreds of probes per host (cipher suites, protocol versions,
    known CVEs); it has no "lite" mode that meaningfully shrinks that.
    STEALTH posture trades the TLS-misconfig signal for the quiet
    footprint, parallel to the traceroute gate.
    """
    if not config.scan.tls_enabled:
        logger.debug("TLS scan disabled by scan_mode posture; skipping")
        return []

    https_eps = [
        ep
        for ep in endpoints
        if ep.url.startswith("https://") and ep.status_code and ep.status_code < 500
    ]
    if not https_eps:
        return []

    testssl = shutil.which("testssl.sh") or shutil.which("testssl")
    if not testssl:
        logger.warning("testssl.sh binary not found; skipping TLS checks")
        return []

    findings: list[RawFinding] = []
    seen_hosts: set[str] = set()

    for ep in https_eps[: config.scan.tls_max_targets]:
        host = urlparse(ep.url).netloc
        if host in seen_hosts:
            continue
        seen_hosts.add(host)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name

        try:
            _run(
                [
                    testssl,
                    "--jsonfile",
                    out_path,
                    "--severity",
                    "LOW",
                    "--quiet",
                    "--nodns",  # skip DNS lookups - we do those separately
                    ep.url,
                ],
                timeout=config.scan.testssl_timeout,
            )

            try:
                with open(out_path) as fh:
                    results = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                logger.debug("testssl: could not read output for %s: %s", host, exc)
                continue

            if not isinstance(results, list):
                continue

            for item in results:
                severity_str = str(item.get("severity", "INFO"))
                if severity_str not in _TESTSSL_SEVERITY_MAP:
                    continue
                test_id = str(item.get("id", ""))
                if test_id in _TESTSSL_SKIP_IDS:
                    continue

                finding_text = str(item.get("finding", ""))
                cve = str(item.get("cve", ""))
                sev = _TESTSSL_SEVERITY_MAP[severity_str]

                evidence = f"Host: {host}\nCheck: {test_id}\nResult: {finding_text}"
                if cve:
                    evidence += f"\nCVE: {cve}"

                findings.append(
                    RawFinding(
                        title=f"TLS: {test_id} - {host}",
                        vuln_class="TLSMisconfiguration",
                        target=ep.url,
                        evidence=evidence,
                        tool="testssl",
                        severity_hint=sev,
                    )
                )

        except Exception as exc:
            logger.debug("testssl failed for %s: %s", host, exc)
        finally:
            with contextlib.suppress(OSError):
                os.unlink(out_path)

    logger.info("TLS check found %d findings across %d hosts", len(findings), len(seen_hosts))
    return findings


def check_dns_email_security(domains: list[str]) -> list[RawFinding]:
    """
    Check SPF and DMARC records for each domain via DNS.

    Accepts both subdomains and root domains; internally deduplicates to
    organisational domains so subdomain sprawl does not produce duplicate
    findings. Checks:

    - Missing SPF -> MEDIUM (anyone can spoof @domain)
    - SPF +all    -> HIGH   (explicitly authorises all senders)
    - Missing DMARC -> MEDIUM (no enforcement policy)
    - DMARC p=none  -> LOW   (monitoring only, no reject/quarantine)
    """
    findings: list[RawFinding] = []
    seen: set[str] = set()

    for hostname in domains:
        domain = _root_domain(hostname)
        if not domain or domain in seen:
            continue
        seen.add(domain)

        spf = _get_spf(domain)
        if spf is None:
            findings.append(
                RawFinding(
                    title=f"Missing SPF record - {domain}",
                    vuln_class="EmailSpoofing",
                    target=domain,
                    evidence=(
                        f"No SPF TXT record found for {domain}.\n"
                        f"Without SPF, any server can send email as @{domain}."
                    ),
                    tool="dns_check",
                    severity_hint=Severity.MEDIUM,
                )
            )
        elif "+all" in spf:
            findings.append(
                RawFinding(
                    title=f"Permissive SPF (+all) - {domain}",
                    vuln_class="EmailSpoofing",
                    target=domain,
                    evidence=(
                        f"SPF record uses +all, which explicitly authorises any server "
                        f"to send email as @{domain}:\n{spf}"
                    ),
                    tool="dns_check",
                    severity_hint=Severity.HIGH,
                )
            )

        dmarc = _get_dmarc(domain)
        if dmarc is None:
            findings.append(
                RawFinding(
                    title=f"Missing DMARC record - {domain}",
                    vuln_class="EmailSpoofing",
                    target=domain,
                    evidence=(
                        f"No DMARC TXT record found at _dmarc.{domain}.\n"
                        f"Without DMARC, spoofed emails pass policy checks even if SPF/DKIM fail."
                    ),
                    tool="dns_check",
                    severity_hint=Severity.MEDIUM,
                )
            )
        elif "p=none" in dmarc:
            findings.append(
                RawFinding(
                    title=f"DMARC p=none (no enforcement) - {domain}",
                    vuln_class="EmailSpoofing",
                    target=domain,
                    evidence=(
                        f"DMARC record exists but policy is p=none - "
                        f"non-conforming emails are reported but not rejected or quarantined:\n"
                        f"{dmarc}"
                    ),
                    tool="dns_check",
                    severity_hint=Severity.LOW,
                )
            )

    logger.info("DNS email security check found %d findings", len(findings))
    return findings
