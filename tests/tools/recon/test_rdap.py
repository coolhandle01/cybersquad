"""tests/tools/recon/test_rdap_bootstrap + lookup.py - RDAP wrapper tests (bootstrap + lookup).

HTTP mocked at the make_response boundary; RDAP sample payloads + the
bootstrap-cache reset come from tests/tools/recon/conftest.py.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models.asset.network import RdapRecord
from tools.recon import rdap

pytestmark = pytest.mark.unit


class TestBootstrapRouting:
    def test_base_url_for_ip_routes_to_arin(self, ipv4_bootstrap, make_response):
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=ipv4_bootstrap)):
            base = rdap._base_url_for_ip("8.8.8.8")
        assert base == "https://rdap.arin.net/registry"

    def test_base_url_for_ip_routes_to_apnic(self, ipv4_bootstrap, make_response):
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=ipv4_bootstrap)):
            base = rdap._base_url_for_ip("1.1.1.1")
        assert base == "https://rdap.apnic.net"

    def test_base_url_for_ip_returns_none_for_unallocated(self, ipv4_bootstrap, make_response):
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=ipv4_bootstrap)):
            base = rdap._base_url_for_ip("10.0.0.1")
        assert base is None

    def test_base_url_for_asn_routes_to_arin(self, asn_bootstrap, make_response):
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=asn_bootstrap)):
            base = rdap._base_url_for_asn(15169)
        assert base == "https://rdap.arin.net/registry"

    def test_base_url_for_asn_returns_none_outside_known_ranges(self, asn_bootstrap, make_response):
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=asn_bootstrap)):
            base = rdap._base_url_for_asn(99999999)
        assert base is None

    def test_bootstrap_cached_across_calls(self, ipv4_bootstrap, make_response):
        with patch(
            "tools.recon.rdap.http.get", return_value=make_response(json=ipv4_bootstrap)
        ) as g:
            rdap._base_url_for_ip("8.8.8.8")
            rdap._base_url_for_ip("8.8.4.4")
        # Two lookups but only one bootstrap fetch - the registry is cached.
        assert g.call_count == 1

    def test_bootstrap_fetch_failure_returns_none(self):
        with patch("tools.recon.rdap.http.get", side_effect=OSError("network down")):
            base = rdap._base_url_for_ip("8.8.8.8")
        assert base is None

    def test_bootstrap_payload_without_services_array(self, make_response):
        # IANA contract specifies a top-level ``services`` array; a
        # response missing it degrades to no-routing rather than crashing.
        with patch(
            "tools.recon.rdap.http.get",
            return_value=make_response(json={"description": "not a real registry"}),
        ):
            assert rdap._base_url_for_ip("8.8.8.8") is None

    def test_bootstrap_payload_not_a_json_object(self, make_response):
        with patch(
            "tools.recon.rdap.http.get",
            return_value=make_response(json=["unexpected", "shape"]),
        ):
            assert rdap._base_url_for_ip("8.8.8.8") is None

    def test_invalid_ip_returns_none_without_bootstrap(self):
        # ipaddress.ip_address rejects bogus values before we hit the
        # registry - no HTTP request fires.
        with patch("tools.recon.rdap.http.get") as g:
            assert rdap._base_url_for_ip("not.an.ip") is None
        g.assert_not_called()

    def test_malformed_bootstrap_entries_skipped(self, make_response):
        # Entries that don't conform to ``[prefixes, urls]`` shape are
        # quietly skipped; the walker continues looking for valid ones.
        broken_then_good = {
            "services": [
                "not a list",
                [["8.0.0.0/9"], "urls is not a list"],
                [["not a cidr"], ["https://rdap.x.test/"]],
                [["8.0.0.0/9"], ["https://rdap.arin.net/registry/"]],
            ]
        }
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=broken_then_good)):
            assert rdap._base_url_for_ip("8.8.8.8") == "https://rdap.arin.net/registry"

    def test_malformed_asn_ranges_skipped(self, make_response):
        broken_then_good = {
            "services": [
                "not a list",
                [["not a range"], ["https://rdap.x.test/"]],
                [["15169-15169"], ["https://rdap.arin.net/registry/"]],
            ]
        }
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=broken_then_good)):
            assert rdap._base_url_for_asn(15169) == "https://rdap.arin.net/registry"

    def test_ipv6_routes_via_v6_bootstrap(self, make_response):
        v6_bootstrap = {
            "services": [
                [["2001:4860::/32"], ["https://rdap.arin.net/registry/"]],
            ]
        }
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=v6_bootstrap)):
            assert rdap._base_url_for_ip("2001:4860:4860::8888") == "https://rdap.arin.net/registry"

    def test_pick_https_url_falls_back_to_http_only(self):
        # Some bootstrap entries list only http:// URLs; we accept those
        # rather than no-routing the lookup.
        assert rdap._pick_https_url(["http://rdap.x.test/"]) == "http://rdap.x.test"

    def test_pick_https_url_returns_none_for_no_strings(self):
        assert rdap._pick_https_url([42, None, {}]) is None

    def test_rir_from_url_none_input(self):
        assert rdap._rir_from_url(None) is None

    def test_asn_bootstrap_entries_with_non_list_fields_skipped(self, make_response):
        # Defensive: bootstrap rows where ``ranges`` or ``urls`` aren't
        # lists are skipped without crashing the walker.
        broken = {
            "services": [
                ["not a list", "also not a list"],
                [[42, "15169-15169"], ["https://rdap.arin.net/registry/"]],
            ]
        }
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=broken)):
            assert rdap._base_url_for_asn(15169) == "https://rdap.arin.net/registry"


# Defensive vCard / entity / event walkers


class TestLookupFailurePaths:
    def test_ip_payload_validation_error_returns_none(
        self, arin_ip_payload, ipv4_bootstrap, make_response
    ):
        # Force ``_parse_rdap_payload`` to raise ValueError by feeding a
        # ``source_url`` longer than the RdapRecord.source_url length cap.
        long_url = "https://rdap.arin.net/registry/ip/8.8.8.8?" + ("x" * 600)
        get = MagicMock(
            side_effect=[
                make_response(json=ipv4_bootstrap),
                make_response(json=arin_ip_payload),
            ]
        )
        with (
            patch("tools.recon.rdap.http.get", get),
            patch.object(rdap, "_base_url_for_ip", return_value=long_url.rstrip("/")),
        ):
            # The long base URL produces an over-long source_url that the
            # RdapRecord's max_length=512 rejects, hitting the ValueError
            # fallback in lookup_rdap_for_ip.
            assert rdap.lookup_rdap_for_ip("8.8.8.8") is None

    def test_asn_http_failure_after_bootstrap(self, asn_bootstrap, make_response):
        get = MagicMock(
            side_effect=[
                make_response(json=asn_bootstrap),
                OSError("connection refused"),
            ]
        )
        with patch("tools.recon.rdap.http.get", get):
            assert rdap.lookup_rdap_for_asn(15169) is None

    def test_asn_response_not_a_json_object(self, asn_bootstrap, make_response):
        get = MagicMock(
            side_effect=[
                make_response(json=asn_bootstrap),
                make_response(json=["unexpected"]),
            ]
        )
        with patch("tools.recon.rdap.http.get", get):
            assert rdap.lookup_rdap_for_asn(15169) is None

    def test_asn_payload_validation_error_returns_none(
        self, arin_asn_payload, asn_bootstrap, make_response
    ):
        long_url = "https://rdap.arin.net/registry/autnum/15169?" + ("y" * 600)
        get = MagicMock(
            side_effect=[
                make_response(json=asn_bootstrap),
                make_response(json=arin_asn_payload),
            ]
        )
        with (
            patch("tools.recon.rdap.http.get", get),
            patch.object(rdap, "_base_url_for_asn", return_value=long_url.rstrip("/")),
        ):
            assert rdap.lookup_rdap_for_asn(15169) is None


# Contact walking


class TestLookupRdapForIp:
    def test_returns_record_for_routed_ip(self, arin_ip_payload, ipv4_bootstrap, make_response):
        get = MagicMock(
            side_effect=[
                make_response(json=ipv4_bootstrap),
                make_response(json=arin_ip_payload),
            ]
        )
        with patch("tools.recon.rdap.http.get", get):
            record = rdap.lookup_rdap_for_ip("8.8.8.8")
        assert isinstance(record, RdapRecord)
        assert record.query == "8.8.8.8"
        assert record.handle == "NET-8-8-8-0-1"
        assert record.source_url == "https://rdap.arin.net/registry/ip/8.8.8.8"
        assert record.rir == "ARIN"

    def test_returns_none_when_bootstrap_misses(self, ipv4_bootstrap, make_response):
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=ipv4_bootstrap)):
            assert rdap.lookup_rdap_for_ip("10.0.0.1") is None

    def test_returns_none_on_http_failure_after_bootstrap(self, ipv4_bootstrap, make_response):
        get = MagicMock(
            side_effect=[
                make_response(json=ipv4_bootstrap),
                OSError("connection refused"),
            ]
        )
        with patch("tools.recon.rdap.http.get", get):
            assert rdap.lookup_rdap_for_ip("8.8.8.8") is None

    def test_returns_none_when_response_not_a_json_object(self, ipv4_bootstrap, make_response):
        get = MagicMock(
            side_effect=[
                make_response(json=ipv4_bootstrap),
                make_response(json=["unexpected", "shape"]),
            ]
        )
        with patch("tools.recon.rdap.http.get", get):
            assert rdap.lookup_rdap_for_ip("8.8.8.8") is None


class TestLookupRdapForAsn:
    def test_returns_record_for_routed_asn(self, arin_asn_payload, asn_bootstrap, make_response):
        get = MagicMock(
            side_effect=[
                make_response(json=asn_bootstrap),
                make_response(json=arin_asn_payload),
            ]
        )
        with patch("tools.recon.rdap.http.get", get):
            record = rdap.lookup_rdap_for_asn(15169)
        assert isinstance(record, RdapRecord)
        assert record.query == "AS15169"
        assert record.handle == "AS15169"
        assert record.registrant_organisation == "Google LLC"
        assert record.source_url == "https://rdap.arin.net/registry/autnum/15169"
        assert record.rir == "ARIN"

    def test_returns_none_outside_known_asn_range(self, asn_bootstrap, make_response):
        with patch("tools.recon.rdap.http.get", return_value=make_response(json=asn_bootstrap)):
            assert rdap.lookup_rdap_for_asn(99999999) is None
