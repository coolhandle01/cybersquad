"""Read the OWASP Amass asset database via ``oamx``.

Amass v5 moved its results into a SQLite asset database and stopped
populating the text output, so the usual ``-o subs.txt`` handoff produces an
empty file and the pipeline downstream of it succeeds having scanned nothing.
``oamx`` is the consumer side of that database; this module is the adapter
between its normalised records and cybersquad's OAM asset shapes.

Read-only by construction: ``oamx`` opens the database with a
``file:...?mode=ro`` URI and cannot start a scan or send traffic. Nothing here
enumerates anything - it reports what Amass already collected, which is what
makes it safe to hand to an agent.

The mapping is close to identity because both sides implement the same
vocabulary. ``oamx``'s per-asset ``sources`` (name + 0-100 confidence) is
``SourceProperty`` field for field; its ``FQDN`` / ``IPAddress`` / ``Netblock``
values are the matching ``models.asset`` types. Where the two disagree, OAM
names win - see the ``cybersquad-oam`` skill.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from pydantic import TypeAdapter

from models import FQDN, IPAddress, IPType, Netblock, SourceProperty

logger = logging.getLogger(__name__)

# oamx view name -> the OAM asset type it selects. Mirrors oamx's own VIEWS
# table; kept here so a typo surfaces as a module-level constant rather than
# an ``unknown view`` error mid-run.
NAMES_VIEW = "names"
ADDRESSES_VIEW = "ips"
NETBLOCKS_VIEW = "cidrs"

# The typed aliases only validate through Pydantic - a bare ``FQDN(x)`` call
# runs no validator - so coercion goes through an adapter and the returned
# shapes are real rather than cosmetic. See models.primitives.
_FQDN_LIST_ADAPTER: TypeAdapter[list[FQDN]] = TypeAdapter(list[FQDN])


class AmassUnavailableError(RuntimeError):
    """``oamx`` is not installed, or no Amass database could be found.

    Carries the message ``oamx`` produced. Those messages are written to be
    read and acted on - "could not find an Amass asset database. Pass --db
    ..." - so they are surfaced verbatim rather than flattened to a generic
    failure.
    """


@dataclass(frozen=True, slots=True)
class AmassFilters:
    """The filters every view shares, as one parameter rather than five.

    Deliberately a plain dataclass and not a model in ``models/``: this is an
    internal call shape between the wrapper and the reader, never a schema an
    agent sees. The LLM-facing surface is each tool's args_schema.
    """

    since: str | None = None
    new_only: bool = False
    resolved_only: bool = False
    min_confidence: int = 0


def _query(
    view: str,
    domains: list[str],
    filters: AmassFilters,
    db: str | None,
) -> list[dict[str, Any]]:
    """Run one ``oamx`` query, translating its failure modes into ours.

    ``oamx`` is imported inside the call rather than at module scope so that
    importing this module - which the OSINT Analyst's package does at build
    time - cannot hard-fail a pipeline that never touches Amass.
    """
    try:
        from oamx.integrations import query
        from oamx.reader import OamxError
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise AmassUnavailableError(
            "oamx is not installed; `pip install oamx` to read an Amass asset database"
        ) from exc

    try:
        # oamx ships no py.typed marker, so mypy sees this as Any; the
        # annotated local is what keeps the return type honest here.
        records: list[dict[str, Any]] = query(
            view,
            domains=domains,
            db=db,
            since=filters.since,
            new_only=filters.new_only,
            resolved_only=filters.resolved_only,
            min_confidence=filters.min_confidence,
        )
    except OamxError as exc:
        raise AmassUnavailableError(str(exc)) from exc
    return records


def _sources(record: dict[str, Any]) -> list[SourceProperty]:
    """Map oamx provenance onto ``SourceProperty``.

    One entry per Amass plugin that asserted the asset. A record with no
    provenance yields an empty list rather than a synthetic "unknown" source -
    absent evidence is not evidence from an unnamed source.
    """
    out: list[SourceProperty] = []
    for source in record.get("sources") or []:
        name = str(source.get("name") or "").strip()
        if not name:
            continue
        confidence = source.get("confidence")
        out.append(
            SourceProperty(
                source=name[:64],
                confidence=int(confidence) if isinstance(confidence, (int, float)) else 0,
            )
        )
    return out


def _ip_type(value: str) -> IPType:
    """IPv4 / IPv6 from the literal itself.

    Both ``IPAddress`` and ``Netblock`` reject a ``type`` that disagrees with
    their address family, so deriving it here rather than trusting Amass's
    ``type`` attribute keeps the producer side consistent by construction.
    """
    return IPType.IPV6 if ":" in value else IPType.IPV4


def _values(records: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    """Non-empty ``(value, record)`` pairs, in oamx's stable sorted order."""
    return [(str(r["value"]), r) for r in records if str(r.get("value") or "").strip()]


def amass_subdomains(
    domains: list[str],
    filters: AmassFilters | None = None,
    *,
    db: str | None = None,
) -> list[FQDN]:
    """Hostnames Amass has already discovered for ``domains``.

    ``filters.resolved_only`` drops names with no DNS record - the ones that
    would cost a scan slot and resolve to nothing. ``filters.new_only`` (with
    ``since``) matches first-seen rather than last-seen, so a host
    re-confirmed by a second data source is not reported as new.
    """
    records = _query(NAMES_VIEW, domains, filters or AmassFilters(), db)
    names = [value for value, _ in _values(records)]
    logger.info("amass: %d subdomains for %s", len(names), ", ".join(domains) or "(unscoped)")
    return _FQDN_LIST_ADAPTER.validate_python(names)


def amass_addresses(
    domains: list[str],
    filters: AmassFilters | None = None,
    *,
    db: str | None = None,
) -> list[IPAddress]:
    """IP addresses Amass associated with ``domains``, with provenance.

    Scoped by graph proximity to an in-scope hostname rather than by string
    match, so a shared CDN's other customers do not arrive with them.
    """
    records = _query(ADDRESSES_VIEW, domains, filters or AmassFilters(), db)

    out: list[IPAddress] = []
    for value, record in _values(records):
        try:
            out.append(IPAddress(address=value, type=_ip_type(value), sources=_sources(record)))
        except ValueError:
            # A value that is not a literal address is a mapping surprise, not
            # a reason to lose the rest of the batch.
            logger.warning("amass: skipping unparseable IPAddress value %r", value)
    return out


def amass_netblocks(
    domains: list[str],
    filters: AmassFilters | None = None,
    *,
    db: str | None = None,
) -> list[Netblock]:
    """Announced prefixes containing the addresses Amass found for ``domains``."""
    records = _query(NETBLOCKS_VIEW, domains, filters or AmassFilters(), db)

    out: list[Netblock] = []
    for value, _record in _values(records):
        try:
            out.append(Netblock(cidr=value, type=_ip_type(value)))
        except ValueError:
            logger.warning("amass: skipping unparseable Netblock value %r", value)
    return out
