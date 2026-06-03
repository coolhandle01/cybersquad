"""tests/tools/recon/nmap/test_service.py - unit tests for the
NmapHostResult -> OAM subgraph decomposition (tools/recon/nmap/service.py).
"""

from __future__ import annotations

import pytest

from models import RelationType
from models.scanner import NmapHostResult, NmapService
from tools.recon.nmap.service import services_from_nmap

pytestmark = pytest.mark.unit


class TestServicesFromNmap:
    def test_decomposes_open_service_with_cpe(self):
        result = NmapHostResult(
            host="example.com",
            services=[
                NmapService(
                    port=22,
                    protocol="tcp",
                    state="open",
                    service="ssh",
                    product="OpenSSH",
                    version="7.4",
                    extra_info="Ubuntu",
                    cpe="cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*",
                    conf=10,
                )
            ],
        )
        assets = services_from_nmap(result)

        # One Service asset, identity <host>:<port>/<proto>, banner in
        # output / attributes (no host / port / cpe on the struct).
        assert len(assets.services) == 1
        svc = assets.services[0]
        assert svc.id == "example.com:22/tcp"
        assert svc.type == "ssh"
        assert svc.output == "Ubuntu"
        assert svc.attributes["product"] == ["OpenSSH"]
        assert svc.attributes["cpe"] == ["cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"]

        # CPE decomposed into Product + ProductRelease assets.
        assert [p.name for p in assets.products] == ["openssh"]
        assert [r.name for r in assets.product_releases] == ["openssh 7.4"]

        # Provenance: every nmap-produced asset carries a SourceProperty stamp,
        # confidence scaled from nmap's 1-10 conf (10) to the OAM 0-100 range.
        assert svc.sources[0].source == "nmap"
        assert svc.sources[0].confidence == 100
        assert assets.products[0].sources[0].confidence == 100
        assert assets.product_releases[0].sources[0].confidence == 100

        # port (host -> Service) + product_used (Service -> ProductRelease) edges.
        port_edge = next(r for r in assets.relations if r.relation_type == RelationType.PORT)
        assert port_edge.from_key == "example.com"
        assert port_edge.to_key == "example.com:22/tcp"
        assert port_edge.port_number == 22
        used_edge = next(r for r in assets.relations if r.label == "product_used")
        assert used_edge.from_key == "example.com:22/tcp"
        assert used_edge.to_key == "openssh 7.4"

    def test_drops_non_open_services(self):
        # OAM is a presence graph: only an *open* service is a node.
        result = NmapHostResult(
            host="example.com",
            services=[
                NmapService(port=80, protocol="tcp", state="open", service="http"),
                NmapService(port=443, protocol="tcp", state="filtered", service="https"),
                NmapService(port=25, protocol="tcp", state="closed", service="smtp"),
            ],
        )
        assets = services_from_nmap(result)
        assert [s.id for s in assets.services] == ["example.com:80/tcp"]

    def test_empty_host_result_yields_no_assets(self):
        assets = services_from_nmap(NmapHostResult(host="example.com"))
        assert assets.services == []
        assert assets.relations == []

    def test_service_without_cpe_has_no_product(self):
        # A service-name-only row (no -sV CPE match) still becomes a Service
        # node + its port edge, but no Product / ProductRelease / product_used.
        result = NmapHostResult(
            host="example.com",
            services=[NmapService(port=6379, protocol="tcp", state="open", service="redis")],
        )
        assets = services_from_nmap(result)
        assert len(assets.services) == 1
        assert assets.products == []
        assert assets.product_releases == []
        assert all(r.label == "port" for r in assets.relations)
