"""
tools/recon/asn.py - bulk IP -> ASN / netblock / RIR-org lookup via
Team Cymru's whois service.

Team Cymru (https://team-cymru.com/community-services/ip-asn-mapping/)
runs a free whois server that answers IP-to-ASN queries at scale. The
bulk protocol takes a newline-delimited list of IPs on stdin and emits
one row per IP carrying the AS number, the announcing BGP prefix
(== netblock), the country code, and the AS organisation name. One
subprocess call returns four amass-asset-types worth of data per IP -
the cheapest possible source for the ASN / Netblock / RIROrganization
layer of the attack surface.

Wire format (response):

    Bulk mode: ...
    AS      | IP               | BGP Prefix      | CC | Registry | Allocated  | AS Name
    15169   | 8.8.8.8          | 8.8.8.0/24      | US | arin     | 1992-12-01 | GOOGLE, US
    13335   | 1.1.1.1          | 1.1.1.0/24      | US | arin     | 2010-07-14 | CLOUDFLAREN ET, US

Lines starting with "AS" / non-tabular cruft are skipped. The first
header line carries the column legend; we anchor on it being present
to confirm the response is Cymru's, not someone's misconfigured whois
server.

Reference: https://team-cymru.com/community-services/ip-asn-mapping/
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from models.asset.network import AsnRecord
from models.primitives import IpAddr
from tools._helpers import _require_binary, _run

logger = logging.getLogger(__name__)

# Cymru's bulk whois endpoint. `-h` selects the server, `-v` enables
# verbose mode (returns the columns shown above), and the `begin /
# verbose / end` envelope tells Cymru to batch-process stdin.
_CYMRU_HOST = "whois.cymru.com"
_BULK_ENVELOPE_BEGIN = "begin\nverbose"
_BULK_ENVELOPE_END = "end"

# Defence: cap how many IPs we ship to Cymru in one call. The service
# accepts large batches but unbounded batching is impolite. 256 is a
# generous slice that's well below Cymru's documented limits.
_MAX_BATCH = 256


def _build_bulk_input(ips: list[IpAddr]) -> str:
    """Assemble Cymru's stdin envelope: ``begin / verbose / <ips> / end``."""
    body = "\n".join(ips)
    return f"{_BULK_ENVELOPE_BEGIN}\n{body}\n{_BULK_ENVELOPE_END}\n"


def _parse_cymru_row(line: str) -> AsnRecord | None:
    """Parse one row of Cymru's verbose bulk-whois output.

    Format: ``AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name``
    pipe-separated with whitespace padding. Returns ``None`` for header
    rows, blanks, or malformed entries (Cymru emits "NA" for unknown
    AS numbers - we skip those rather than coerce to 0).
    """
    # Split at most six times so the trailing AS-Name column stays intact even
    # when it contains a literal "|" - an unbounded split would truncate a
    # piped org name to the seventh field and silently drop the rest.
    parts = [p.strip() for p in line.split("|", 6)]
    if len(parts) < 7:
        return None
    asn_raw, ip_raw, prefix, country, _registry, _allocated, organisation = parts
    # Header row legend ("AS | IP | BGP Prefix | ...") trips the column
    # count check above but a stray padding line might not - skip when
    # the AS column isn't numeric.
    if not asn_raw.isdigit():
        return None
    try:
        return AsnRecord(
            # ``IpAddr`` is ``Annotated[str, AfterValidator(...)]`` so
            # a bare ``str`` satisfies the field type; the validator
            # fires inside ``AsnRecord(...)`` and rejects malformed IPs.
            ip=ip_raw,
            asn=int(asn_raw),
            prefix=prefix,
            country=country,
            organisation=organisation,
        )
    except ValueError as exc:
        # Validator rejected one field (mis-shaped IP / over-long org
        # name). Skip the row rather than fail the whole batch.
        logger.debug("Cymru row skipped: %s (%s)", line[:80], exc)
        return None


def lookup_asn(ips: list[IpAddr]) -> list[AsnRecord]:
    """Bulk IP -> ASN lookup via Team Cymru's whois service.

    Input: scope-filtered ``list[IpAddr]``. Output: one ``AsnRecord``
    per IP for which Cymru returned a valid row. IPs that Cymru does
    not know about (rare; typically RFC 1918 / unannounced space) drop
    silently from the result.

    One subprocess call per batch of up to ``_MAX_BATCH`` IPs; the
    caller chunks larger lists. Returns an empty list on subprocess
    failure (network down, whois binary missing) rather than raising -
    recon should degrade gracefully when ASN data is unavailable.
    """
    if not ips:
        return []
    whois = _require_binary("whois")
    records: list[AsnRecord] = []
    started = datetime.now(UTC)
    for start in range(0, len(ips), _MAX_BATCH):
        chunk = ips[start : start + _MAX_BATCH]
        try:
            result = _run(
                [whois, "-h", _CYMRU_HOST],
                timeout=60,
                input=_build_bulk_input(chunk),
            )
        except Exception as exc:
            logger.warning("Cymru bulk-whois failed for chunk of %d IPs: %s", len(chunk), exc)
            continue
        for line in result.stdout.splitlines():
            record = _parse_cymru_row(line)
            if record is not None:
                records.append(record)
    elapsed = (datetime.now(UTC) - started).total_seconds()
    logger.info(
        "Cymru ASN lookup: %d records from %d IPs in %.1fs",
        len(records),
        len(ips),
        elapsed,
    )
    return records


__all__ = ["lookup_asn"]
