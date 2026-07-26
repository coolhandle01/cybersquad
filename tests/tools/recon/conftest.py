"""Recon-scoped test fixtures: RDAP sample payloads + the bootstrap-cache
reset. Kept here (not in tests/fixtures/) because they are narrow to the
RDAP suite - the autouse reset must apply to every RDAP test but nowhere
broader, and the payloads are only meaningful to the RDAP parser tests.
"""

from __future__ import annotations

import pytest

from tools.recon import rdap


@pytest.fixture(autouse=True)
def _clear_bootstrap_cache():
    """Reset the module-level bootstrap cache so tests don't bleed state."""
    rdap._bootstrap_cache.clear()
    yield
    rdap._bootstrap_cache.clear()


@pytest.fixture()
def arin_ip_payload() -> dict:
    """Real-shape ARIN RDAP response for 8.8.8.8, trimmed to the fields the
    parser reads (entities + nested abuse entity + events + handle)."""
    return {
        "objectClassName": "ip network",
        "handle": "NET-8-8-8-0-1",
        "startAddress": "8.8.8.0",
        "endAddress": "8.8.8.255",
        "entities": [
            {
                "objectClassName": "entity",
                "handle": "GOGL",
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Google LLC"],
                        ["kind", {}, "text", "org"],
                    ],
                ],
                "entities": [
                    {
                        "handle": "ZG39-ARIN",
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [
                                ["version", {}, "text", "4.0"],
                                ["fn", {}, "text", "Abuse"],
                                ["email", {}, "text", "network-abuse@google.com"],
                            ],
                        ],
                    }
                ],
            }
        ],
        "events": [
            {"eventAction": "registration", "eventDate": "1992-12-01T05:00:00-05:00"},
            {"eventAction": "last changed", "eventDate": "2014-03-14T16:52:05-04:00"},
        ],
    }


@pytest.fixture()
def arin_asn_payload() -> dict:
    """Real-shape ARIN RDAP response for autnum/15169."""
    return {
        "objectClassName": "autnum",
        "handle": "AS15169",
        "startAutnum": 15169,
        "endAutnum": 15169,
        "name": "GOOGLE",
        "entities": [
            {
                "handle": "GOGL",
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]],
            }
        ],
        "events": [{"eventAction": "registration", "eventDate": "2000-03-30T00:00:00Z"}],
    }


@pytest.fixture()
def ipv4_bootstrap() -> dict:
    """Trimmed IANA IPv4 RDAP bootstrap registry - enough to route the tests."""
    return {
        "services": [
            [["8.0.0.0/9"], ["https://rdap.arin.net/registry/"]],
            [["1.0.0.0/8"], ["https://rdap.apnic.net/"]],
        ],
    }


@pytest.fixture()
def asn_bootstrap() -> dict:
    """Trimmed IANA ASN RDAP bootstrap registry."""
    return {
        "services": [
            [["1-1876", "15169-15169"], ["https://rdap.arin.net/registry/"]],
            [["131072-141625"], ["https://rdap.apnic.net/"]],
        ],
    }
