"""
tests/squad/osint_analyst/test_enrichment.py - contract + invocation tests
for the OSINT Analyst's post-sweep pivot tools in
``squad/osint_analyst/enrichment.py``.

The pivot tools (``Lookup IP Assets``, ``Lookup RDAP for ASN``, ``Discover
Host Services``) are the "explore, don't just record" surface from #181:
the agent reaches for them *after* the initial sweep to enrich IPs it
surfaced, pivot on an ASN, or deep-scan a single host's open ports.

This file carries the wrapper-invocation + scope-decision cases; the
generic args_schema contract sweep (explicit schema wired, every field
described, closed-world mapping) is parametrised over ``MEMBER.schemas``
in ``test_args_schemas.py`` and picks these tools up automatically once
they are registered.
"""

from __future__ import annotations

import pytest

from models import IPType
from models.asset import IPAddress, IpEnrichment, Service
from models.asset.network import RdapRecord
from models.scanner import NmapHostResult, NmapMode, NmapScanResult, NmapScripts, NmapService
from squad.osint_analyst import (
    _DiscoverHostServicesArgs,
    _LookupIpAssetsArgs,
    _LookupRdapAsnArgs,
    discover_host_services_tool,
    lookup_ip_assets_tool,
    lookup_rdap_asn_tool,
)

pytestmark = pytest.mark.unit


class TestLookupIpAssets:
    """``Lookup IP Assets`` wraps ``compose_ip_enrichment`` - no scope filter.

    The IPs come from the sweep, which was already scope-filtered upstream
    (the programme scope model is FQDN-shaped, so there is no IP-level
    scope alias to apply). The wrapper is a thin typed pass-through.
    """

    def test_schema_accepts_ip_list(self) -> None:
        """A list of dotted-quad IPs validates without raising."""
        instance = _LookupIpAssetsArgs.model_validate({"ips": ["1.2.3.4", "8.8.8.8"]})
        assert instance.ips == ["1.2.3.4", "8.8.8.8"]

    def test_schema_rejects_non_ip(self) -> None:
        """A hostname where an IP was asked for rejects at the boundary."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            _LookupIpAssetsArgs.model_validate({"ips": ["not-an-ip"]})

    def test_returns_composed_bundle(self, invoke_tool, monkeypatch) -> None:
        """The wrapper returns ``compose_ip_enrichment``' typed bundle verbatim."""
        composed = IpEnrichment(ip_addresses=[IPAddress(address="1.2.3.4", type=IPType.IPV4)])
        captured: dict[str, object] = {}

        def _fake_compose(ips):
            captured["ips"] = ips
            return composed

        monkeypatch.setattr("squad.osint_analyst.enrichment.compose_ip_enrichment", _fake_compose)

        result = invoke_tool(lookup_ip_assets_tool, ips=["1.2.3.4", "8.8.8.8"])

        assert result == composed
        assert captured["ips"] == ["1.2.3.4", "8.8.8.8"]


class TestLookupRdapAsn:
    """``Lookup RDAP for ASN`` wraps ``lookup_rdap_for_asn`` - no scope filter.

    The ASN-side pivot: IP-side RDAP is already in the ``Lookup IP Assets``
    enrichment bundle, so this is the genuinely new lookup (who owns the AS,
    what's its registrant / abuse contact). The ASN is a number the agent
    read off an ``autonomous_systems`` entry, not a scope-bearing target.
    """

    def test_schema_accepts_asn(self) -> None:
        """A 32-bit ASN validates without raising."""
        instance = _LookupRdapAsnArgs.model_validate({"asn": 13335})
        assert instance.asn == 13335

    def test_schema_rejects_negative_asn(self) -> None:
        """ASN below the 0..2^32-1 range rejects at the boundary."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            _LookupRdapAsnArgs.model_validate({"asn": -1})

    def test_schema_rejects_out_of_range_asn(self) -> None:
        """ASN above the 32-bit range rejects at the boundary."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            _LookupRdapAsnArgs.model_validate({"asn": 4_294_967_296})

    def test_schema_rejects_non_numeric_asn(self) -> None:
        """An ``AS``-prefixed string is not coercible to int and rejects."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            _LookupRdapAsnArgs.model_validate({"asn": "AS13335"})

    def test_returns_registrant_bundle(self, invoke_tool, monkeypatch) -> None:
        """The wrapper decomposes the RDAP record into faithful OAM assets."""
        record = RdapRecord(
            query="AS13335", handle="AS13335", registrant_organisation="Cloudflare, Inc."
        )
        captured: dict[str, object] = {}

        def _fake_lookup(asn):
            captured["asn"] = asn
            return record

        monkeypatch.setattr("squad.osint_analyst.enrichment.lookup_rdap_for_asn", _fake_lookup)

        result = invoke_tool(lookup_rdap_asn_tool, asn=13335)

        assert [a.number for a in result.autnum_records] == [13335]
        assert [o.name for o in result.organizations] == ["Cloudflare, Inc."]
        assert any(r.label == "managed_by" for r in result.relations)
        assert captured["asn"] == 13335

    def test_returns_empty_bundle_on_miss(self, invoke_tool, monkeypatch) -> None:
        """A bootstrap / lookup miss yields an empty bundle, not a crash."""
        monkeypatch.setattr("squad.osint_analyst.enrichment.lookup_rdap_for_asn", lambda asn: None)

        result = invoke_tool(lookup_rdap_asn_tool, asn=64512)

        assert result.autnum_records == []
        assert result.organizations == []
        assert result.relations == []


class TestDeepScanHost:
    """``Discover Host Services`` wraps ``nmap_scan`` in SERVICE_VERSION mode -
    this one DOES scope-filter.

    Unlike the IP / ASN lookups, the target is an FQDN, and the programme
    scope model is FQDN-shaped, so ``host`` is a ``TargetFQDN`` (single,
    loud-reject). An out-of-scope host raises at validation before any
    nmap subprocess fires. The wrapper deep-scans one host's known-open
    ports, returning the host's open ``Service`` assets (with CPE +
    provenance) and writing them to the host's ``services.json``.
    """

    def test_schema_accepts_in_scope_host(self, programme_in_workspace, target_apex) -> None:
        """An in-scope hostname + port list validates without raising."""
        instance = _DiscoverHostServicesArgs.model_validate(
            {"host": f"api.{target_apex}", "ports": [22, 443]}
        )
        assert instance.host == f"api.{target_apex}"
        assert instance.ports == [22, 443]

    def test_schema_rejects_out_of_scope_host(self, programme_in_workspace, bystander_url) -> None:
        """A ``TargetFQDN`` host outside the programme scope rejects loudly."""
        from urllib.parse import urlparse

        from pydantic import ValidationError

        oos_host = urlparse(bystander_url).hostname
        with pytest.raises(ValidationError, match="not in the selected programme's scope"):
            _DiscoverHostServicesArgs.model_validate({"host": oos_host, "ports": [443]})

    def test_schema_rejects_url_in_host(self, programme_in_workspace, target_url) -> None:
        """A URL where a bare hostname is expected trips the FQDN primitive."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            _DiscoverHostServicesArgs.model_validate({"host": target_url, "ports": [443]})

    def test_runs_service_version_scan_and_persists_services(
        self, invoke_tool, programme_in_workspace, target_apex, monkeypatch
    ) -> None:
        """The wrapper runs nmap in SERVICE_VERSION mode, decomposes the open
        services into the OAM subgraph (Service + Product / ProductRelease +
        port / product_used edges), and writes each facet to the host dir."""
        from tools.recon_host_store import (
            load_host_product_releases,
            load_host_products,
            load_host_relations,
            load_host_services,
        )

        host = f"api.{target_apex}"
        host_result = NmapHostResult(
            host=host,
            services=[
                NmapService(
                    port=22,
                    protocol="tcp",
                    state="open",
                    service="ssh",
                    product="OpenSSH",
                    version="7.4",
                    cpe="cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*",
                ),
                # A filtered port is not a present service - it must NOT
                # become a Service node (OAM is a presence graph).
                NmapService(port=443, protocol="tcp", state="filtered", service="https"),
            ],
        )
        captured_hosts: list[str] = []
        captured_kwargs: dict[str, object] = {}

        def _fake_nmap_scan(hosts, **kwargs):
            captured_hosts.extend(hosts)
            captured_kwargs.update(kwargs)
            return NmapScanResult(mode=NmapMode.SERVICE_VERSION, hosts=[host_result])

        monkeypatch.setattr("squad.osint_analyst.enrichment.nmap_scan", _fake_nmap_scan)

        result = invoke_tool(discover_host_services_tool, host=host, ports=[22, 443])

        # nmap invoked correctly
        assert captured_hosts == [host]
        assert captured_kwargs["mode"] == NmapMode.SERVICE_VERSION
        assert captured_kwargs["scripts"] == NmapScripts.DEFAULT
        assert captured_kwargs["ports"] == [22, 443]

        # Returns OAM Service assets - only the OPEN service; the filtered
        # port is dropped. host:port is the id; the banner is in attributes.
        assert [s.id for s in result] == [f"{host}:22/tcp"]
        svc = result[0]
        assert isinstance(svc, Service)
        assert svc.type == "ssh"
        assert svc.attributes["product"] == ["OpenSSH"]
        assert svc.attributes["cpe"] == ["cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"]

        # ... and persisted: the Service facet, the Product / ProductRelease
        # the CPE decomposed to, and the port / product_used edges.
        assert [s.id for s in load_host_services(host)] == [f"{host}:22/tcp"]
        assert [p.name for p in load_host_products(host)] == ["openssh"]
        assert [r.name for r in load_host_product_releases(host)] == ["openssh 7.4"]
        assert {r.label for r in load_host_relations(host)} == {"port", "product_used"}

    def test_returns_empty_when_nmap_finds_nothing(
        self, invoke_tool, programme_in_workspace, target_apex, monkeypatch
    ) -> None:
        """When nmap returns no host rows (host down / scan failed), the
        wrapper returns an empty list - the OA always gets a typed result
        back - and writes no services.json."""
        from tools.recon_host_store import load_host_services

        host = f"api.{target_apex}"

        monkeypatch.setattr(
            "squad.osint_analyst.enrichment.nmap_scan",
            lambda hosts, **kwargs: NmapScanResult(mode=NmapMode.SERVICE_VERSION, hosts=[]),
        )

        result = invoke_tool(discover_host_services_tool, host=host, ports=[443])

        assert result == []
        assert load_host_services(host) == []
