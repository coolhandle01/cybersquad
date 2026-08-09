"""
DNS resolution and subdomain-takeover detection via dnsx.

The OSINT Analyst calls Detect Takeover Candidates to flag subdomains
whose CNAME points to a known-vulnerable provider or whose CNAME chain
dangles (CNAME exists but does not resolve to any A record) - both
classic takeover-vulnerability shapes.

dnsx is the projectdiscovery DNS resolver; install via install-tools.sh.
"""

from __future__ import annotations

import json
import logging

from pydantic import BaseModel

# TakeoverCandidate lives in models/dns.py per the typed-shapes-live-
# in-models rule. Re-exported here so existing ``from tools.recon.dnsx
# import TakeoverCandidate`` consumers keep working; the canonical
# import path is ``from models import TakeoverCandidate``.
from config import config
from models.dns import PtrRecord, TakeoverCandidate
from models.primitives import IpAddr
from tools._helpers import _require_binary, _run

logger = logging.getLogger(__name__)

# Curated subset of the can-i-take-over-xyz catalogue
# (https://github.com/EdOverflow/can-i-take-over-xyz). Each entry maps a
# CNAME suffix to the service it identifies. When the OA's sweep finds a
# subdomain whose CNAME ends in one of these suffixes, the next step is to
# HTTP-probe the host and check for the service-specific "not found" body
# string - if it matches, the subdomain can be claimed by registering on
# the provider.
#
# We intentionally keep this list to widely-encountered, high-confidence
# patterns. Subtle providers that flip vulnerability status frequently
# (e.g. Fastly only with no custom domain claimed) sit at the boundary;
# we include them but the agent should treat the result as a candidate,
# not a confirmation.
_TAKEOVER_FINGERPRINTS: list[tuple[str, str]] = [
    # AWS
    (".s3.amazonaws.com", "AWS S3"),
    (".s3-website", "AWS S3 (website)"),
    (".elasticbeanstalk.com", "AWS Elastic Beanstalk"),
    (".cloudfront.net", "AWS CloudFront"),
    # Azure
    (".cloudapp.net", "Azure (Cloud Services classic)"),
    (".cloudapp.azure.com", "Azure (Cloud Services)"),
    (".azurewebsites.net", "Azure Web Apps"),
    (".blob.core.windows.net", "Azure Blob Storage"),
    (".azureedge.net", "Azure CDN"),
    (".azure-api.net", "Azure API Management"),
    (".trafficmanager.net", "Azure Traffic Manager"),
    # PaaS / hosting
    (".herokuapp.com", "Heroku"),
    (".herokudns.com", "Heroku DNS"),
    (".vercel.app", "Vercel"),
    (".netlify.app", "Netlify"),
    (".netlify.com", "Netlify"),
    (".surge.sh", "Surge.sh"),
    (".pantheonsite.io", "Pantheon"),
    (".readthedocs.io", "Read the Docs"),
    (".fly.dev", "Fly.io"),
    # Static / pages
    (".github.io", "GitHub Pages"),
    (".gitlab.io", "GitLab Pages"),
    (".bitbucket.io", "Bitbucket Pages"),
    # SaaS / docs / support
    (".helpjuice.com", "Helpjuice"),
    (".helpscoutdocs.com", "Help Scout"),
    (".intercom.help", "Intercom"),
    (".statuspage.io", "Statuspage"),
    (".tumblr.com", "Tumblr"),
    (".tictail.com", "Tictail"),
    (".uservoice.com", "UserVoice"),
    (".zendesk.com", "Zendesk"),
    # Misc
    (".gitbook.io", "GitBook"),
    (".tilda.ws", "Tilda"),
    (".webflow.io", "Webflow"),
    (".wordpress.com", "WordPress"),
    (".strikinglydns.com", "Strikingly"),
    (".launchrock.com", "LaunchRock"),
    # Fastly: CNAME pattern matches but exploitability requires the
    # service-side claim status; treat as candidate.
    (".fastly.net", "Fastly"),
]


class DNSRecord(BaseModel):
    """One host's resolved DNS records, as returned by dnsx."""

    hostname: str
    a_records: list[str] = []
    cname: list[str] = []
    # The response TTL dnsx reports (retryabledns ``ttl``); one value per host
    # response, carried onto the OAM DNSRecordProperty / RRHeader. 0 when dnsx
    # omitted it.
    ttl: int = 0


def _match_fingerprint(cname: str) -> str | None:
    """Return the service name if ``cname`` matches a known takeover pattern."""
    target = cname.rstrip(".").lower()
    for suffix, service in _TAKEOVER_FINGERPRINTS:
        if target.endswith(suffix):
            return service
    return None


def resolve_records(hostnames: list[str]) -> list[DNSRecord]:
    """Resolve A and CNAME records for ``hostnames`` via dnsx.

    Returns one ``DNSRecord`` per input host that dnsx emitted output for.
    Hosts that resolve to nothing at all (NXDOMAIN with no CNAME) are
    omitted from the result.
    """
    if not hostnames:
        return []

    dnsx = _require_binary("dnsx")
    input_data = "\n".join(h.strip() for h in hostnames if h.strip())
    if not input_data:
        return []

    result = _run(
        [
            dnsx,
            "-a",
            "-cname",
            "-json",
            "-silent",
            "-rate-limit",
            str(config.scan.dnsx_rate_limit),
            "-t",
            str(config.scan.dnsx_threads),
        ],
        timeout=180,
        input=input_data,
    )
    records: list[DNSRecord] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.debug("Skipping dnsx line: %s (%s)", line[:80], exc)
            continue
        hostname = entry.get("host", "").strip().lower()
        if not hostname:
            continue
        records.append(
            DNSRecord(
                hostname=hostname,
                a_records=entry.get("a") or [],
                cname=entry.get("cname") or [],
                ttl=max(0, int(entry.get("ttl") or 0)),
            )
        )
    logger.info("dnsx resolved %d/%d hosts", len(records), len(hostnames))
    return records


def detect_takeover_candidates(hostnames: list[str]) -> list[TakeoverCandidate]:
    """Flag subdomains whose CNAME points to a known-vulnerable provider or
    whose CNAME chain dangles.

    A "candidate" is exactly that - the OA must follow up with an HTTP
    probe to confirm the takeover fingerprint (Annotate Host the candidate
    HIGH priority with a note pointing the PT at the service-specific
    confirmation step).
    """
    candidates: list[TakeoverCandidate] = []
    for record in resolve_records(hostnames):
        for cname in record.cname:
            service = _match_fingerprint(cname)
            if service is not None:
                candidates.append(
                    TakeoverCandidate(
                        hostname=record.hostname,
                        cname=cname,
                        reason="cname_to_vulnerable_provider",
                        service=service,
                    )
                )
                # One candidate per host even if multiple CNAMEs match -
                # the first match is enough to flag it for the agent.
                break
        else:
            # No CNAME matched a fingerprint. Check for a dangling CNAME -
            # a CNAME exists but the chain produced no A records.
            if record.cname and not record.a_records:
                candidates.append(
                    TakeoverCandidate(
                        hostname=record.hostname,
                        cname=record.cname[0],
                        reason="dangling_cname",
                        service=None,
                    )
                )
    return candidates


def resolve_ptr(ips: list[IpAddr]) -> list[PtrRecord]:
    """Reverse-DNS lookup for ``ips`` via dnsx.

    Maps each IP to whatever name(s) the in-addr.arpa zone publishes
    for it (the inverse of an A record). Returns one ``PtrRecord`` per
    input IP that dnsx emitted output for; IPs with no PTR drop
    silently from the result.

    Defensive: degrades to an empty list on subprocess failure or no
    valid output rather than raising into the recon path. Hostnames
    that trip the FQDN validator (RFC 1123 violations from oddly-shaped
    PTR records) drop the record - the PTR signal is only useful when
    the resolved name is itself a valid hostname.
    """
    if not ips:
        return []

    dnsx = _require_binary("dnsx")
    input_data = "\n".join(ip.strip() for ip in ips if ip.strip())
    if not input_data:
        return []

    try:
        result = _run(
            [
                dnsx,
                "-ptr",
                "-resp",
                "-json",
                "-silent",
                "-rate-limit",
                str(config.scan.dnsx_rate_limit),
                "-t",
                str(config.scan.dnsx_threads),
            ],
            timeout=180,
            input=input_data,
        )
    except Exception as exc:
        logger.warning("dnsx PTR lookup failed: %s", exc)
        return []

    records: list[PtrRecord] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.debug("Skipping dnsx PTR line: %s (%s)", line[:80], exc)
            continue
        ip = (entry.get("host") or "").strip()
        ptr_raw = entry.get("ptr") or []
        if not ip or not isinstance(ptr_raw, list):
            continue
        hostnames = [h.rstrip(".") for h in ptr_raw if isinstance(h, str)]
        try:
            records.append(PtrRecord(ip=ip, hostnames=hostnames))
        except ValueError as exc:
            # A hostname tripped the FQDN validator or the IP failed
            # ``IpAddr`` shape. Retry without the optional hostnames -
            # an IP-only PtrRecord still carries the "we asked, got
            # nothing legible" signal vs the silent drop above.
            logger.debug("dnsx PTR row degraded (dropping hostnames): %s", exc)
            try:
                records.append(PtrRecord(ip=ip))
            except ValueError as exc2:
                logger.debug("dnsx PTR row skipped (IP rejected): %s", exc2)
                continue
    logger.info("dnsx PTR resolved %d/%d IPs", len(records), len(ips))
    return records


__all__ = [
    "DNSRecord",
    "PtrRecord",
    "TakeoverCandidate",
    "detect_takeover_candidates",
    "resolve_ptr",
    "resolve_records",
]
