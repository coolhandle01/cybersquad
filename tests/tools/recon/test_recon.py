"""tests/tools/recon/test_recon.py - unit tests for the tools/recon package
entry point (tools/recon/__init__.py).

Covers the seeding constants the orchestrator reads to decide which scope
items are worth enumerating, and ``run_recon`` itself - the pipeline that
stitches every recon helper into the ``AttackGraph`` the downstream agents
consume. Every helper is mocked so the test asserts composition, not the
helpers' own behaviour (those live in the per-source test modules).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from models import Endpoint, IPAddress, IpEnrichment
from models.h1 import ScopeType
from tools.recon import _ACTIVE_RECON_TYPES, _CODE_HOSTS

pytestmark = pytest.mark.unit


class TestSeedingConstants:
    """
    Regression: URL-type scope items pointing into third-party code hosting infra
    (e.g. github.com/cloudflare) must not be used as subfinder seeds.
    H1 returns URL for both bare domains and wildcard patterns; OTHER for products.
    """

    def test_url_type_is_active_recon(self):
        assert ScopeType.URL in _ACTIVE_RECON_TYPES

    def test_wildcard_type_is_active_recon(self):
        assert ScopeType.WILDCARD in _ACTIVE_RECON_TYPES

    def test_other_type_is_not_active_recon(self):
        assert ScopeType.OTHER not in _ACTIVE_RECON_TYPES

    def test_code_hosts_blocks_github(self):
        assert "github.com" in _CODE_HOSTS

    def test_code_hosts_blocks_gitlab(self):
        assert "gitlab.com" in _CODE_HOSTS


class TestRunRecon:
    def test_assembles_attack_graph_from_recon_pipeline(self, programme, target_apex):
        # Smoke test for the orchestrator: every recon helper mocked,
        # verifies the AttackGraph it builds carries the expected
        # composition (subdomains the scope guard accepted, endpoints
        # probed, ports scanned, tech collated, traceroute hops keyed
        # by host, IP enrichment composed from resolve_records).
        from tools.recon import run_recon
        from tools.recon.dnsx import DNSRecord

        ep = Endpoint(url=f"https://api.{target_apex}/", status_code=200, technologies=["nginx"])
        dns_record = DNSRecord(hostname=f"api.{target_apex}", a_records=["8.8.8.8"], cname=[])
        ip_enrichment = IpEnrichment(ip_addresses=[IPAddress(address="8.8.8.8", type="IPv4")])
        with (
            patch(
                "tools.recon.enumerate_subdomains",
                return_value=[f"api.{target_apex}", "out.example.org"],
            ),
            patch("tools.recon.probe_endpoints", return_value=[ep]),
            patch("tools.recon.port_scan", return_value={f"api.{target_apex}": [443]}),
            patch("tools.recon.discover_paths", return_value=[]),
            patch("tools.recon.check_tls", return_value=[]),
            patch("tools.recon.check_dns_email_security", return_value=[]),
            patch("tools.recon.run_traceroute", return_value={}),
            patch("tools.recon.resolve_records", return_value=[dns_record]) as mock_resolve,
            patch("tools.recon.compose_ip_enrichment", return_value=ip_enrichment) as mock_compose,
        ):
            attack_graph = run_recon(programme)

        # Out-of-scope host filtered; the in-scope api.* survives.
        assert f"api.{target_apex}" in attack_graph.subdomains
        assert attack_graph.endpoints == [ep]
        assert attack_graph.open_ports == {f"api.{target_apex}": [443]}
        assert "nginx" in attack_graph.technologies

        # IP enrichment: A records from resolve_records feed
        # compose_ip_enrichment, the result lands on AttackGraph.ip_enrichment.
        mock_resolve.assert_called_once_with([f"api.{target_apex}"])
        mock_compose.assert_called_once_with(["8.8.8.8"])
        assert attack_graph.ip_enrichment == ip_enrichment
        assert attack_graph.ip_enrichment.ip_addresses[0].address == "8.8.8.8"

        # The same A records surface as OAM DNSRecordProperty entries plus
        # their BasicDNSRelation edges on the graph.
        assert [p.data for p in attack_graph.dns_records] == ["8.8.8.8"]
        assert attack_graph.dns_records[0].header.rr_type == 1  # A
        assert [r.to_key for r in attack_graph.relations] == ["8.8.8.8"]
        assert attack_graph.relations[0].label == "a_record"

    def test_port_scan_receives_hostnames_not_urls(self, programme, target_apex):
        # Regression: nmap scans hosts, not URLs. run_recon must extract the
        # hostname from each live Endpoint.url before handing it to
        # port_scan - feeding the full ``https://.../`` URL makes nmap fail
        # to resolve the target and keys open_ports by URL instead of host.
        from tools.recon import run_recon

        live = Endpoint(url=f"https://api.{target_apex}/admin", status_code=200)
        dead = Endpoint(url=f"https://down.{target_apex}/", status_code=503)
        with (
            patch("tools.recon.enumerate_subdomains", return_value=[f"api.{target_apex}"]),
            patch("tools.recon.probe_endpoints", return_value=[live, dead]),
            patch("tools.recon.port_scan", return_value={}) as mock_port_scan,
            patch("tools.recon.discover_paths", return_value=[]),
            patch("tools.recon.check_tls", return_value=[]),
            patch("tools.recon.check_dns_email_security", return_value=[]),
            patch("tools.recon.run_traceroute", return_value={}),
            patch("tools.recon.resolve_records", return_value=[]),
            patch("tools.recon.compose_ip_enrichment", return_value=IpEnrichment()),
        ):
            run_recon(programme)

        # Bare hostname extracted (scheme + path stripped); the 5xx endpoint
        # is filtered out, so only the live host reaches nmap.
        mock_port_scan.assert_called_once_with([f"api.{target_apex}"])

    def test_promotes_in_scope_tls_sans_to_subdomains(self, programme, target_apex):
        # When httpx runs in WEB_INVENTORY mode, Endpoint.tls_sans carries
        # the SAN-leaked hostnames. run_recon promotes the ones the scope
        # guard accepts onto subdomains so downstream enrichment sees them
        # in the same pass.
        from tools.recon import run_recon

        ep = Endpoint(
            url=f"https://api.{target_apex}/",
            status_code=200,
            tls_sans=[
                f"admin.{target_apex}",  # in-scope, should promote
                "bystander.example.org",  # out-of-scope, should filter
            ],
        )
        with (
            patch(
                "tools.recon.enumerate_subdomains",
                return_value=[f"api.{target_apex}"],
            ),
            patch("tools.recon.probe_endpoints", return_value=[ep]),
            patch("tools.recon.port_scan", return_value={}),
            patch("tools.recon.discover_paths", return_value=[]),
            patch("tools.recon.check_tls", return_value=[]),
            patch("tools.recon.check_dns_email_security", return_value=[]),
            patch("tools.recon.run_traceroute", return_value={}),
            patch("tools.recon.resolve_records", return_value=[]),
            patch("tools.recon.compose_ip_enrichment", return_value=IpEnrichment()),
        ):
            attack_graph = run_recon(programme)

        # In-scope SAN promoted; out-of-scope SAN filtered.
        assert f"api.{target_apex}" in attack_graph.subdomains
        assert f"admin.{target_apex}" in attack_graph.subdomains
        assert "bystander.example.org" not in attack_graph.subdomains

    def test_no_san_promotion_when_endpoints_carry_no_sans(self, programme, target_apex):
        # TECH_DETECT-mode endpoints have empty tls_sans (no -tls-grab) -
        # the promotion path is a no-op and subdomains stays as the
        # enumerate_subdomains output filtered through the scope guard.
        from tools.recon import run_recon

        ep = Endpoint(url=f"https://api.{target_apex}/", status_code=200)
        with (
            patch(
                "tools.recon.enumerate_subdomains",
                return_value=[f"api.{target_apex}"],
            ),
            patch("tools.recon.probe_endpoints", return_value=[ep]),
            patch("tools.recon.port_scan", return_value={}),
            patch("tools.recon.discover_paths", return_value=[]),
            patch("tools.recon.check_tls", return_value=[]),
            patch("tools.recon.check_dns_email_security", return_value=[]),
            patch("tools.recon.run_traceroute", return_value={}),
            patch("tools.recon.resolve_records", return_value=[]),
            patch("tools.recon.compose_ip_enrichment", return_value=IpEnrichment()),
        ):
            attack_graph = run_recon(programme)

        assert attack_graph.subdomains == [f"api.{target_apex}"]
