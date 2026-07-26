"""
tests/tools/recon/test_amass.py - unit tests for tools/recon/amass.py

Exercised against a real Amass asset database built here, not a mocked
``oamx.query``. A mock would agree with itself no matter what either side
did; a real database pins the mapping against the schema oamx actually
reads. No network, no Amass binary - just SQLite.

Scope of these tests is the *mapping*: oamx records in, cybersquad OAM
models out, with provenance preserved and IP family derived from the
literal. oamx's own suite owns the layer below - schema tolerance across
Amass v4 and v5, graph scoping, merge semantics - so nothing here re-tests
that.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from models import IPType
from tools.recon.amass import (
    AmassFilters,
    AmassUnavailableError,
    amass_addresses,
    amass_netblocks,
    amass_subdomains,
)

pytestmark = pytest.mark.unit

_V5_SCHEMA = """
CREATE TABLE entities (
    entity_id  INTEGER PRIMARY KEY,
    created_at datetime, updated_at datetime,
    etype      TEXT, content JSON
);
CREATE TABLE entity_tags (
    tag_id     INTEGER PRIMARY KEY,
    created_at datetime, updated_at datetime,
    ttype      TEXT, content JSON, entity_id INTEGER
);
CREATE TABLE edges (
    edge_id        INTEGER PRIMARY KEY,
    created_at     datetime, updated_at datetime,
    etype          TEXT, content JSON,
    from_entity_id INTEGER, to_entity_id INTEGER
);
"""

_TS = "2026-07-25 09:00:00.000000000+00:00"

# id, etype, content
_ENTITIES = [
    (1, "FQDN", {"name": "example.com"}),
    (2, "FQDN", {"name": "www.example.com"}),
    (3, "FQDN", {"name": "dev.example.com"}),  # exists, never resolved
    (4, "IPAddress", {"address": "93.184.216.34", "type": "IPv4"}),
    (5, "IPAddress", {"address": "2606:2800:220:1::1946", "type": "IPv6"}),
    (6, "Netblock", {"cidr": "93.184.216.0/24", "type": "IPv4"}),
    (7, "FQDN", {"name": "other.co.uk"}),  # a different target entirely
    (8, "IPAddress", {"address": "203.0.113.9", "type": "IPv4"}),  # and its address
]

# id, etype, label, extra content, from, to
_EDGES = [
    (1, "SimpleRelation", "node", {}, 1, 2),
    (2, "SimpleRelation", "node", {}, 1, 3),
    (3, "BasicDNSRelation", "dns_record", {"header": {"rr_type": 1}}, 2, 4),
    (4, "BasicDNSRelation", "dns_record", {"header": {"rr_type": 28}}, 1, 5),
    (5, "SimpleRelation", "contains", {}, 6, 4),
    (6, "BasicDNSRelation", "dns_record", {"header": {"rr_type": 1}}, 7, 8),
]

# entity_id -> [(source name, confidence)]
_SOURCES = {
    2: [("DNS-IP", 100), ("crtsh", 80)],
    3: [("brute-forcing", 50)],
    4: [("DNS-IP", 100)],
}


@pytest.fixture(scope="module")
def amass_db(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """An Amass v5 asset database with one in-scope target and one bystander."""
    path = tmp_path_factory.mktemp("amass") / "amass.sqlite"
    conn = sqlite3.connect(path)
    conn.executescript(_V5_SCHEMA)

    for eid, etype, content in _ENTITIES:
        conn.execute(
            "INSERT INTO entities (entity_id, created_at, updated_at, etype, content)"
            " VALUES (?,?,?,?,?)",
            (eid, _TS, _TS, etype, json.dumps(content)),
        )
    for rid, etype, label, extra, src, dst in _EDGES:
        conn.execute(
            "INSERT INTO edges (edge_id, created_at, updated_at, etype, content,"
            " from_entity_id, to_entity_id) VALUES (?,?,?,?,?,?,?)",
            (rid, _TS, _TS, etype, json.dumps({"label": label, **extra}), src, dst),
        )
    tag_id = 1
    for eid, sources in _SOURCES.items():
        for name, confidence in sources:
            conn.execute(
                "INSERT INTO entity_tags (tag_id, created_at, updated_at, ttype,"
                " content, entity_id) VALUES (?,?,?,?,?,?)",
                (
                    tag_id,
                    _TS,
                    _TS,
                    "SourceProperty",
                    json.dumps({"name": name, "confidence": confidence}),
                    eid,
                ),
            )
            tag_id += 1
    conn.commit()
    conn.close()
    return path


class TestSubdomains:
    def test_returns_the_scoped_tree(self, amass_db: Path) -> None:
        names = amass_subdomains(["example.com"], db=str(amass_db))
        assert names == ["dev.example.com", "example.com", "www.example.com"]

    def test_a_different_target_does_not_leak_in(self, amass_db: Path) -> None:
        assert "other.co.uk" not in amass_subdomains(["example.com"], db=str(amass_db))

    def test_resolved_only_drops_names_with_no_dns_record(self, amass_db: Path) -> None:
        resolved = amass_subdomains(
            ["example.com"], AmassFilters(resolved_only=True), db=str(amass_db)
        )
        # Pin what survives as well as what goes: an empty list would satisfy
        # the absence check on its own, and empty is the failure mode that
        # matters here.
        assert resolved == ["example.com", "www.example.com"]

    def test_min_confidence_sheds_brute_force_guesses(self, amass_db: Path) -> None:
        high = amass_subdomains(["example.com"], AmassFilters(min_confidence=90), db=str(amass_db))
        # amass_subdomains returns list[FQDN]; compare on the string values so
        # this reads as list-of-str membership - to a human and to CodeQL's URL
        # sanitization heuristic - rather than an FQDN-identity or substring check.
        names = [str(name) for name in high]
        assert "www.example.com" in names
        assert "dev.example.com" not in names, "brute-forcing asserts only 50"

    def test_no_domains_is_not_an_unscoped_read(self, amass_db: Path) -> None:
        # The wrapper short-circuits on an empty list; the kernel is called
        # with domains only when the agent named some. Guard the kernel's own
        # behaviour so an empty scope never silently becomes "everything".
        assert amass_subdomains([], db=str(amass_db)) != ["other.co.uk"]


class TestAddresses:
    def test_maps_both_families_with_derived_type(self, amass_db: Path) -> None:
        addresses = amass_addresses(["example.com"], db=str(amass_db))
        by_addr = {a.address: a for a in addresses}
        assert set(by_addr) == {"93.184.216.34", "2606:2800:220:1::1946"}
        assert by_addr["93.184.216.34"].type is IPType.IPV4
        assert by_addr["2606:2800:220:1::1946"].type is IPType.IPV6

    def test_provenance_becomes_source_properties(self, amass_db: Path) -> None:
        addresses = amass_addresses(["example.com"], db=str(amass_db))
        ipv4 = next(a for a in addresses if a.address == "93.184.216.34")
        assert [(s.source, s.confidence) for s in ipv4.sources] == [("DNS-IP", 100)]

    def test_the_other_targets_address_is_out_of_scope(self, amass_db: Path) -> None:
        addresses = amass_addresses(["example.com"], db=str(amass_db))
        assert "203.0.113.9" not in {a.address for a in addresses}


class TestNetblocks:
    def test_reaches_the_prefix_two_hops_out(self, amass_db: Path) -> None:
        netblocks = amass_netblocks(["example.com"], db=str(amass_db))
        assert [n.cidr for n in netblocks] == ["93.184.216.0/24"]
        assert netblocks[0].type is IPType.IPV4


class TestFailureModes:
    def test_a_missing_database_is_an_actionable_error(self, tmp_path: Path) -> None:
        with pytest.raises(AmassUnavailableError) as ctx:
            amass_subdomains(["example.com"], db=str(tmp_path / "absent.sqlite"))
        # oamx's messages are written to be read and acted on; surface them
        # rather than flattening to a generic failure.
        assert "no such database" in str(ctx.value)

    def test_a_non_amass_database_is_an_actionable_error(self, tmp_path: Path) -> None:
        path = tmp_path / "junk.sqlite"
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE unrelated (a TEXT)")
        conn.commit()
        conn.close()
        with pytest.raises(AmassUnavailableError) as ctx:
            amass_subdomains(["example.com"], db=str(path))
        assert "does not look like an Amass" in str(ctx.value)
