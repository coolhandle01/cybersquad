"""tests/tools/recon/test_rdap_parsing.py - RDAP wrapper tests (parsing).

HTTP mocked at the make_response boundary; RDAP sample payloads + the
bootstrap-cache reset come from tests/tools/recon/conftest.py.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from models.asset.network import ContactRole
from tools.recon import rdap

pytestmark = pytest.mark.unit


class TestDefensiveWalkers:
    def test_vcard_properties_not_a_list(self):
        # Outer shape valid, inner property list malformed.
        assert rdap._vcard_field(["vcard", "not a list of props"], "fn") is None

    def test_vcard_property_too_short(self):
        # Each property must be ``[name, params, type, value]`` (len >= 4);
        # short ones are skipped.
        vcard = ["vcard", [["fn", {}, "text"], ["email", {}, "text", "a@b.test"]]]
        # First prop is too short; walker continues to the next.
        assert rdap._vcard_field(vcard, "email") == "a@b.test"

    def test_walk_entities_skips_non_dict_entries(self):
        entities = ["not a dict", {"roles": ["registrant"], "handle": "X"}]
        matches = rdap._walk_entities_for_role(entities, "registrant")
        assert len(matches) == 1
        assert matches[0]["handle"] == "X"

    def test_parse_event_events_not_a_list(self):
        assert rdap._parse_event("not a list", "registration") is None

    def test_parse_event_event_date_not_string(self):
        events = [{"eventAction": "registration", "eventDate": 12345}]
        assert rdap._parse_event(events, "registration") is None

    def test_parse_event_skips_non_dict_entries(self):
        events = [
            "not a dict",
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
        ]
        result = rdap._parse_event(events, "registration")
        assert result is not None
        assert result.year == 2020

    def test_registrant_without_fn_leaves_org_none(self):
        payload = {
            "entities": [
                {"roles": ["registrant"], "vcardArray": ["vcard", []]},
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert record.registrant_organisation is None

    def test_abuse_entity_without_email_leaves_email_none(self):
        payload = {
            "entities": [
                {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"]]]},
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert record.abuse_email is None


# Failure paths on lookup_rdap_for_ip / _for_asn parity coverage


class TestContactWalking:
    def test_walks_full_contact_set(self):
        payload = {
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "Example Corp"],
                            ["email", {}, "text", "registry@example.com"],
                            ["tel", {}, "text", "+1-555-0001"],
                        ],
                    ],
                    "entities": [
                        {
                            "roles": ["abuse"],
                            "vcardArray": [
                                "vcard",
                                [
                                    ["fn", {}, "text", "Abuse Desk"],
                                    ["email", {}, "text", "abuse@example.com"],
                                ],
                            ],
                        },
                        {
                            "roles": ["technical"],
                            "vcardArray": [
                                "vcard",
                                [
                                    ["fn", {}, "text", "Tech NOC"],
                                    ["email", {}, "text", "tech@example.com"],
                                    ["tel", {}, "text", "+1-555-0002"],
                                ],
                            ],
                        },
                    ],
                }
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        roles = {c.role for c in record.contacts}
        assert {ContactRole.REGISTRANT, ContactRole.ABUSE, ContactRole.TECHNICAL} <= roles
        # The convenience-access flat fields still derive from the contacts.
        assert record.registrant_organisation == "Example Corp"
        assert record.abuse_email == "abuse@example.com"

    def test_skips_entity_with_no_useful_fields(self):
        # An entity with role but neither name, email, nor phone is
        # filtered upstream of contact construction.
        payload = {
            "entities": [
                {
                    "roles": ["admin"],
                    "vcardArray": ["vcard", []],
                }
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert record.contacts == []

    def test_unknown_role_is_dropped(self):
        # The parser walks ContactRole values only; an entity whose role
        # is outside our catalogue does not project onto an OTHER bucket.
        payload = {
            "entities": [
                {
                    "roles": ["billing"],  # not in ContactRole
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "Billing"],
                            ["email", {}, "text", "billing@example.com"],
                        ],
                    ],
                }
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert record.contacts == []

    def test_malformed_email_degrades_to_email_less_contact(self):
        # An RDAP server returning a non-shaped email trips the Email
        # validator; _build_contact retries without the email and keeps
        # the rest of the contact intact.
        payload = {
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "Abuse Desk"],
                            ["email", {}, "text", "not an email"],
                        ],
                    ],
                }
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert len(record.contacts) == 1
        assert record.contacts[0].name == "Abuse Desk"
        assert record.contacts[0].email is None

    def test_overlong_name_drops_contact_entirely(self):
        # The Email validator passed; the name length cap rejects on
        # both the initial construction and the email-stripped retry,
        # so the contact drops on the floor.
        payload = {
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "x" * 300],
                            ["email", {}, "text", "abuse@example.com"],
                        ],
                    ],
                }
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert record.contacts == []


# Defensive payload parsing


class TestParseRdapPayload:
    def test_extracts_handle_org_abuse_and_events(self, arin_ip_payload):
        record = rdap._parse_rdap_payload(
            arin_ip_payload,
            query="8.8.8.8",
            source_url="https://rdap.arin.net/registry/ip/8.8.8.8",
        )
        assert record.handle == "NET-8-8-8-0-1"
        assert record.registrant_organisation == "Google LLC"
        assert record.abuse_email == "network-abuse@google.com"
        assert record.rir == "ARIN"
        assert record.registered_at == datetime(
            1992, 12, 1, 5, 0, 0, tzinfo=timezone(timedelta(hours=-5))
        )
        assert record.last_changed_at == datetime(
            2014, 3, 14, 16, 52, 5, tzinfo=timezone(timedelta(hours=-4))
        )

    def test_empty_payload_yields_record_with_only_query_and_url(self):
        record = rdap._parse_rdap_payload(
            {},
            query="8.8.8.8",
            source_url="https://rdap.arin.net/registry/ip/8.8.8.8",
        )
        assert record.query == "8.8.8.8"
        assert record.source_url == "https://rdap.arin.net/registry/ip/8.8.8.8"
        assert record.handle is None
        assert record.registrant_organisation is None
        assert record.abuse_email is None
        assert record.registered_at is None

    def test_missing_abuse_entity_leaves_email_none(self, arin_ip_payload):
        # Strip the nested abuse entity from the registrant.
        payload = {**arin_ip_payload}
        payload["entities"] = [{**payload["entities"][0], "entities": []}]
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert record.registrant_organisation == "Google LLC"
        assert record.abuse_email is None

    def test_rir_unknown_when_source_url_not_in_catalogue(self):
        record = rdap._parse_rdap_payload(
            {"handle": "X"}, query="x", source_url="https://rdap.example.test/x"
        )
        assert record.rir is None

    def test_malformed_event_date_skipped(self):
        payload = {
            "events": [
                {"eventAction": "registration", "eventDate": "not a date"},
                {"eventAction": "last changed", "eventDate": "2020-01-01T00:00:00Z"},
            ]
        }
        record = rdap._parse_rdap_payload(payload, query="x", source_url="https://x")
        assert record.registered_at is None
        assert record.last_changed_at is not None


# vCard field extraction


class TestVcardField:
    def test_extracts_fn(self):
        vcard = ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Acme Co"]]]
        assert rdap._vcard_field(vcard, "fn") == "Acme Co"

    def test_returns_none_when_field_absent(self):
        vcard = ["vcard", [["version", {}, "text", "4.0"]]]
        assert rdap._vcard_field(vcard, "email") is None

    def test_returns_none_on_malformed_outer_shape(self):
        assert rdap._vcard_field("not a vcard", "fn") is None
        assert rdap._vcard_field([], "fn") is None


# End-to-end lookup paths
