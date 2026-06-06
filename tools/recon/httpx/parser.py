"""Httpx NDJSON output parser.

``_parse_ndjson(stdout, mode)`` is the only public function. Each
NDJSON line becomes one ``Endpoint``. Mode controls which fields the
parser pulls off the JSON object:

* ``LIVE``: ``url`` + ``status_code`` only.
* ``TECH_DETECT``: + ``tech`` -> ``technologies`` (the raw httpx
  tech-detect strings, the detecting tool's own vocabulary).
* ``WEB_INVENTORY``: + ``favicon`` + ``tls.subject_alt_names`` ->
  ``favicon_hash`` / ``tls_sans``.

Defensive throughout. A malformed JSON line is logged at DEBUG and
skipped (one bad row does not blast the batch). A ``ValueError`` from
the FQDN validator on a SAN degrades the row's optional fields - we
retry the ``Endpoint(...)`` construction without them so the LIVE /
tech signal is still captured.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from urllib.parse import urlparse

from models.asset import Endpoint, SourceProperty, TLSCertificate
from models.scanner import HttpxMode

# httpx directly probes the endpoint, so its observation carries a
# full-confidence OAM provenance stamp.
_HTTPX_SOURCE = "httpx"
_HTTPX_CONFIDENCE = 100

logger = logging.getLogger(__name__)


def _parse_cert_datetime(value: object) -> datetime | None:
    """Coerce an httpx RFC-3339 validity timestamp to ``datetime``.

    Returns ``None`` for a missing / non-string / unparseable value so a
    single malformed date degrades only that field rather than dropping
    the whole cert.
    """
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _build_tls_certificate(tls_block: object, sans: list[str], url: str) -> TLSCertificate | None:
    """Build the OAM ``TLSCertificate`` asset from httpx's ``tls`` block.

    Returns ``None`` when no cert was grabbed (non-WEB_INVENTORY modes,
    plain HTTP) or the host cannot be derived. Defensive: httpx versions
    vary in which cert fields they emit, so every field beyond ``host``
    is best-effort, and a boundary-cap rejection drops the cert rather
    than the row. ``subject_alt_names`` is passed through verbatim as the
    cert's own ``list[str]``: wildcards / IP SANs that the FQDN-typed
    ``Endpoint.tls_sans`` rejected are captured faithfully here.
    """
    if not isinstance(tls_block, dict) or not tls_block:
        return None
    host = urlparse(url).hostname
    if not host:
        return None
    fingerprint = tls_block.get("fingerprint_hash")
    sha256 = fingerprint.get("sha256") if isinstance(fingerprint, dict) else None
    try:
        return TLSCertificate(
            host=host,
            subject_common_name=tls_block.get("subject_cn"),
            issuer=tls_block.get("issuer_cn") or tls_block.get("issuer_org"),
            serial=tls_block.get("serial"),
            fingerprint_sha256=sha256,
            not_before=_parse_cert_datetime(tls_block.get("not_before")),
            not_after=_parse_cert_datetime(tls_block.get("not_after")),
            subject_alt_names=sans,
        )
    except ValueError as exc:
        logger.debug("tls cert dropped (%s)", exc)
        return None


def _parse_ndjson(stdout: str, mode: HttpxMode) -> list[Endpoint]:
    """Parse httpx's NDJSON output into a list of typed ``Endpoint`` rows."""
    endpoints: list[Endpoint] = []
    for line in stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.debug("Skipping httpx line: %s (%s)", line[:80], exc)
            continue
        if not isinstance(entry, dict):
            continue

        raw_tech = entry.get("tech", []) if mode != HttpxMode.LIVE else []
        # httpx v1.6+ emits the favicon MMH3 hash under ``favicon``;
        # older versions used ``favicon_path``. Accept either.
        favicon = entry.get("favicon") or entry.get("favicon_path")
        # TLS SANs live under ``tls.subject_alt_names`` when ``-tls-grab``
        # ran. Strings only - drop non-string entries up front.
        tls_block = entry.get("tls") or {}
        sans_raw = tls_block.get("subject_alt_names", []) if isinstance(tls_block, dict) else []
        sans_filtered: list[str] = [san for san in sans_raw if isinstance(san, str)]

        sources = [SourceProperty(source=_HTTPX_SOURCE, confidence=_HTTPX_CONFIDENCE)]
        try:
            ep = Endpoint(
                url=entry.get("url", ""),
                status_code=entry.get("status_code"),
                technologies=raw_tech,
                favicon_hash=favicon if isinstance(favicon, str) else None,
                tls_sans=sans_filtered,
                sources=sources,
            )
        except ValueError as exc:
            # One field rejected (likely a SAN not RFC-1123-shaped or a
            # mis-formatted favicon hash). Retry without the optional
            # fields - LIVE / tech signal is still useful.
            logger.debug("httpx row degraded (dropping optional fields): %s", exc)
            try:
                ep = Endpoint(
                    url=entry.get("url", ""),
                    status_code=entry.get("status_code"),
                    technologies=raw_tech,
                    sources=sources,
                )
            except ValueError as exc2:
                logger.debug("httpx row skipped: %s", exc2)
                continue
        # Attach the full cert (independent of the tls_sans degrade above:
        # the cert's SANs are list[str], so it survives wildcards the
        # FQDN-typed tls_sans rejected). model_copy avoids re-validating
        # the already-built Endpoint.
        cert = _build_tls_certificate(tls_block, sans_filtered, ep.url)
        if cert is not None:
            ep = ep.model_copy(update={"tls_certificate": cert})
        endpoints.append(ep)
    return endpoints


__all__ = ["_parse_ndjson"]
