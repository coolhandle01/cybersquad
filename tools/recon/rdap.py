"""
tools/recon/rdap.py - IP / ASN RDAP (RFC 7483) lookup.

Sibling to ``tools/recon/asn.py``. Where Cymru returns a flat pipe-
delimited row (ASN + netblock + AS-name + country mashed into a single
string), RDAP gives us the structured-registrant entry that amass's
``RIROrganization`` asset takes as its input: registrant organisation,
abuse contact, registration / last-change events, all as separate
typed fields.

Wire protocol:

1. IANA publishes a bootstrap registry that maps IP ranges / ASN
   ranges to the RIR (ARIN / RIPE / APNIC / LACNIC / AFRINIC) that
   serves them. We fetch the bootstrap once per process and cache it
   in memory.

2. Given a query IP or ASN, we look up the serving RIR's base RDAP URL
   and hit ``<base>/ip/<addr>`` or ``<base>/autnum/<n>``. The RIR's
   RDAP server returns JSON in the RFC 7483 shape.

3. We walk the response defensively - RIRs vary in which entity roles
   they surface and which events they emit. Missing fields degrade to
   ``None`` on the ``RdapRecord``; one rough-shaped response does not
   block the lookup of the other.

References:
* RFC 7483 - JSON Responses for the Registration Data Access Protocol
* RFC 9224 - Finding the Authoritative Registration Data Access
  Protocol (RDAP) Service
* IANA bootstrap registries:
  https://data.iana.org/rdap/ipv4.json,
  https://data.iana.org/rdap/ipv6.json,
  https://data.iana.org/rdap/asn.json
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime
from typing import Any

from models.asset.network import Contact, ContactRole, RdapRecord
from models.primitives import IpAddr
from tools import http

logger = logging.getLogger(__name__)

_BOOTSTRAP_IPV4_URL = "https://data.iana.org/rdap/ipv4.json"
_BOOTSTRAP_IPV6_URL = "https://data.iana.org/rdap/ipv6.json"
_BOOTSTRAP_ASN_URL = "https://data.iana.org/rdap/asn.json"

# In-process cache for the IANA bootstrap registries. Each entry's
# value is the parsed ``services`` array per RFC 9224: a list of
# ``[<list of prefixes>, <list of base URLs>]`` pairs. Cached at first
# lookup; recon runs share one cache for the process lifetime.
_bootstrap_cache: dict[str, list[Any]] = {}

# Map RIR base-URL hostname to a short canonical name. Used to populate
# RdapRecord.rir from the endpoint URL the bootstrap registry returned,
# without depending on the RIR setting that name in their response.
_RIR_BY_HOST: dict[str, str] = {
    "rdap.arin.net": "ARIN",
    "rdap.db.ripe.net": "RIPE",
    "rdap.apnic.net": "APNIC",
    "rdap.lacnic.net": "LACNIC",
    "rdap.afrinic.net": "AFRINIC",
}


def _fetch_bootstrap(url: str) -> list[Any]:
    """Fetch and parse one IANA bootstrap registry. Cached per process.

    Returns the ``services`` array; ``[]`` on any failure so the caller
    can degrade gracefully instead of raising into the recon path.
    """
    if url in _bootstrap_cache:
        return _bootstrap_cache[url]
    try:
        response = http.get(url, timeout=15)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        logger.warning("RDAP bootstrap fetch failed (%s): %s", url, exc)
        return []
    services = payload.get("services") if isinstance(payload, dict) else None
    if not isinstance(services, list):
        logger.warning("RDAP bootstrap %s has no services array", url)
        return []
    _bootstrap_cache[url] = services
    return services


def _base_url_for_ip(ip: str) -> str | None:
    """Find the authoritative RDAP base URL for ``ip`` via the bootstrap.

    Walks the v4 / v6 bootstrap registry (whichever the address shape
    matches), returning the first base URL whose prefix list contains
    the address. ``None`` if the bootstrap is unreachable or no prefix
    matches (e.g. RFC 1918 / unallocated space).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    services = _fetch_bootstrap(_BOOTSTRAP_IPV6_URL if addr.version == 6 else _BOOTSTRAP_IPV4_URL)
    for entry in services:
        if not (isinstance(entry, list) and len(entry) >= 2):
            continue
        prefixes, urls = entry[0], entry[1]
        if not (isinstance(prefixes, list) and isinstance(urls, list)):
            continue
        for prefix in prefixes:
            try:
                if addr in ipaddress.ip_network(prefix, strict=False):
                    return _pick_https_url(urls)
            except ValueError:
                continue
    return None


def _base_url_for_asn(asn: int) -> str | None:
    """Find the authoritative RDAP base URL for ``asn`` via the bootstrap.

    ASN bootstrap entries express ranges as ``"start-end"`` strings
    (single ASNs as ``"n"``). Walks them looking for the range that
    contains ``asn``; returns the first base URL found, or ``None``.
    """
    services = _fetch_bootstrap(_BOOTSTRAP_ASN_URL)
    for entry in services:
        if not (isinstance(entry, list) and len(entry) >= 2):
            continue
        ranges, urls = entry[0], entry[1]
        if not (isinstance(ranges, list) and isinstance(urls, list)):
            continue
        for r in ranges:
            if not isinstance(r, str):
                continue
            try:
                start, _, end = r.partition("-")
                lo = int(start)
                hi = int(end) if end else lo
            except ValueError:
                continue
            if lo <= asn <= hi:
                return _pick_https_url(urls)
    return None


def _pick_https_url(urls: list[Any]) -> str | None:
    """Prefer the HTTPS endpoint when the bootstrap lists multiple."""
    for url in urls:
        if isinstance(url, str) and url.startswith("https://"):
            return url.rstrip("/")
    for url in urls:
        if isinstance(url, str):
            return url.rstrip("/")
    return None


def _rir_from_url(url: str | None) -> str | None:
    """Best-effort canonical RIR name from the endpoint hostname."""
    if not url:
        return None
    for host, name in _RIR_BY_HOST.items():
        if host in url:
            return name
    return None


def _vcard_field(vcard_array: object, field_name: str) -> str | None:
    """Pull one named field (``fn`` / ``email``) from a jCard array.

    jCard (RFC 7095) shape: ``["vcard", [[name, params, type, value], ...]]``.
    Walks the inner property list, returning the first matching value.
    """
    if not (isinstance(vcard_array, list) and len(vcard_array) >= 2):
        return None
    properties = vcard_array[1]
    if not isinstance(properties, list):
        return None
    for prop in properties:
        if not (isinstance(prop, list) and len(prop) >= 4):
            continue
        if prop[0] == field_name and isinstance(prop[3], str):
            return prop[3]
    return None


def _walk_entities_for_role(entities: object, role: str) -> list[dict[str, Any]]:
    """Collect entities (including nested sub-entities) carrying ``role``.

    RDAP entities may nest sub-entities (an abuse contact attached to a
    registrant). The walker recurses one level deep, which covers what
    every RIR actually emits today.
    """
    matches: list[dict[str, Any]] = []
    if not isinstance(entities, list):
        return matches
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles")
        if isinstance(roles, list) and role in roles:
            matches.append(entity)
        sub = entity.get("entities")
        if isinstance(sub, list):
            matches.extend(_walk_entities_for_role(sub, role))
    return matches


def _parse_event(events: object, action: str) -> datetime | None:
    """Extract the timestamp for the first matching ``eventAction``."""
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("eventAction") != action:
            continue
        raw = event.get("eventDate")
        if not isinstance(raw, str):
            continue
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
    return None


def _build_contact(entity: dict[str, Any], role: ContactRole) -> Contact | None:
    """Build one ``Contact`` from an RDAP entity + the role it carries.

    Defensive against the ``Email`` validator: a vCard ``email`` field
    that isn't shaped like an email (rare, but RIRs are inconsistent)
    drops the email but keeps the rest of the contact rather than
    failing the whole record. ``None`` only when the entity produces
    no useful fields at all.
    """
    vcard = entity.get("vcardArray")
    name = _vcard_field(vcard, "fn")
    email = _vcard_field(vcard, "email")
    phone = _vcard_field(vcard, "tel")
    if not (name or email or phone):
        return None
    try:
        return Contact(role=role, email=email, name=name, phone=phone)
    except ValueError:
        # Email validator rejected the email shape (or a length cap
        # bit). Retry without the email - the rest of the contact is
        # still useful.
        try:
            return Contact(role=role, name=name, phone=phone)
        except ValueError as exc:
            logger.debug("contact dropped (role=%s): %s", role.value, exc)
            return None


def _parse_rdap_payload(payload: dict[str, Any], query: str, source_url: str) -> RdapRecord:
    """Defensively build an ``RdapRecord`` from an RDAP JSON response."""
    handle = payload.get("handle") if isinstance(payload.get("handle"), str) else None
    entities = payload.get("entities")

    contacts: list[Contact] = []
    for role in ContactRole:
        for ent in _walk_entities_for_role(entities, role.value):
            contact = _build_contact(ent, role)
            if contact is not None:
                contacts.append(contact)

    # The convenience-access flat fields read off the contacts list -
    # one walk, two derived shortcuts the OA reads most often.
    registrant_organisation = next(
        (c.name for c in contacts if c.role is ContactRole.REGISTRANT and c.name),
        None,
    )
    abuse_email = next(
        (c.email for c in contacts if c.role is ContactRole.ABUSE and c.email),
        None,
    )

    return RdapRecord(
        query=query,
        handle=handle,
        rir=_rir_from_url(source_url),
        registrant_organisation=registrant_organisation,
        abuse_email=abuse_email,
        registered_at=_parse_event(payload.get("events"), "registration"),
        last_changed_at=_parse_event(payload.get("events"), "last changed"),
        source_url=source_url,
        contacts=contacts,
    )


def lookup_rdap_for_ip(ip: IpAddr) -> RdapRecord | None:
    """RDAP lookup for one IP. Returns ``None`` on any failure."""
    base = _base_url_for_ip(ip)
    if not base:
        logger.debug("No RDAP base URL for IP %s (bootstrap miss)", ip)
        return None
    url = f"{base}/ip/{ip}"
    try:
        response = http.get(url, timeout=30)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        logger.warning("RDAP lookup failed (%s): %s", url, exc)
        return None
    if not isinstance(payload, dict):
        logger.warning("RDAP response from %s is not a JSON object", url)
        return None
    try:
        return _parse_rdap_payload(payload, query=ip, source_url=url)
    except ValueError as exc:
        logger.warning("RDAP response from %s did not validate: %s", url, exc)
        return None


def lookup_rdap_for_asn(asn: int) -> RdapRecord | None:
    """RDAP lookup for one ASN. Returns ``None`` on any failure."""
    base = _base_url_for_asn(asn)
    if not base:
        logger.debug("No RDAP base URL for ASN %d (bootstrap miss)", asn)
        return None
    url = f"{base}/autnum/{asn}"
    try:
        response = http.get(url, timeout=30)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        logger.warning("RDAP lookup failed (%s): %s", url, exc)
        return None
    if not isinstance(payload, dict):
        logger.warning("RDAP response from %s is not a JSON object", url)
        return None
    try:
        return _parse_rdap_payload(payload, query=f"AS{asn}", source_url=url)
    except ValueError as exc:
        logger.warning("RDAP response from %s did not validate: %s", url, exc)
        return None


__all__ = ["lookup_rdap_for_asn", "lookup_rdap_for_ip"]
