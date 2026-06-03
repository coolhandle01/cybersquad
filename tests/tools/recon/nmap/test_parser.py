"""tests/tools/recon/nmap/test_parser.py - unit tests for tools/recon/nmap/parser.py."""

from __future__ import annotations

import pytest

from tools.recon.nmap.parser import _parse_xml

pytestmark = pytest.mark.unit


class TestParseXml:
    def test_parses_multi_host_with_banners(self, nmap_xml_two_hosts):
        results = _parse_xml(nmap_xml_two_hosts)
        assert len(results) == 2

        first = results[0]
        assert first.host == "93.184.216.34"
        assert len(first.services) == 2
        ports = {s.port for s in first.services}
        assert ports == {80, 22}

        nginx_svc = next(s for s in first.services if s.port == 80)
        assert nginx_svc.product == "nginx"
        assert nginx_svc.version == "1.18.0"

        ssh_svc = next(s for s in first.services if s.port == 22)
        assert ssh_svc.product == "OpenSSH"
        assert ssh_svc.version == "7.6p1"
        assert ssh_svc.extra_info == "Ubuntu"

    def test_empty_xml_returns_empty(self):
        assert _parse_xml("") == []

    def test_no_hosts_xml_returns_empty(self, nmap_xml_no_hosts):
        assert _parse_xml(nmap_xml_no_hosts) == []

    def test_malformed_xml_returns_empty(self):
        # Defensive - mid-scan truncation / nmap crash mid-output -> the
        # parser returns an empty list rather than raising.
        assert _parse_xml("this is not xml") == []

    def test_skips_host_without_address(self):
        # <host> with no <address> child - skip rather than raise.
        xml = "<?xml version='1.0'?><nmaprun><host></host></nmaprun>"
        assert _parse_xml(xml) == []

    def test_skips_host_with_empty_addr_attribute(self):
        # <address> exists but addr="" - we have no host identifier to
        # land the row against, so the host is skipped.
        xml = (
            "<?xml version='1.0'?><nmaprun>"
            '<host><address addr="" addrtype="ipv4"/></host>'
            "</nmaprun>"
        )
        assert _parse_xml(xml) == []

    def test_skips_port_with_out_of_range_portid(self):
        # NmapService.port is constrained to 1..65535. A nmap row with
        # portid=70000 trips the validator; the port is dropped but the
        # host row is kept.
        xml = (
            "<?xml version='1.0'?><nmaprun>"
            '<host><address addr="1.1.1.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="70000">'
            '<state state="open"/></port></ports>'
            "</host></nmaprun>"
        )
        results = _parse_xml(xml)
        assert len(results) == 1
        assert results[0].services == []

    def test_service_name_only_used_when_product_absent(self):
        # When nmap emits a service name but no product, the parser
        # uses the service name as the banner string (port-number guess
        # rather than banner-grabbed).
        xml = (
            "<?xml version='1.0'?><nmaprun>"
            '<host><address addr="1.1.1.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22">'
            '<state state="open"/><service name="ssh"/></port></ports>'
            "</host></nmaprun>"
        )
        results = _parse_xml(xml)
        assert len(results) == 1
        assert results[0].services[0].service == "ssh"
        assert results[0].services[0].product is None
        # No <service conf> attribute -> confidence defaults to 0.
        assert results[0].services[0].conf == 0

    def test_skips_host_when_host_validator_rejects_addr(self):
        # NmapHostResult.host is typed FQDN | IpAddr; a non-routable
        # string trips the validator and the row drops on the floor.
        xml = (
            "<?xml version='1.0'?><nmaprun>"
            '<host><address addr="not a valid host" addrtype="ipv4"/></host>'
            "</nmaprun>"
        )
        assert _parse_xml(xml) == []

    def test_captures_application_cpe_from_service(self):
        # nmap emits one or more <cpe> children per service; the parser
        # captures the application CPE, normalised to the 2.3 formatted
        # string, on NmapService.cpe (preferring it over the host-OS CPE).
        xml = (
            "<?xml version='1.0'?><nmaprun>"
            '<host><address addr="1.1.1.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22">'
            '<state state="open"/>'
            '<service name="ssh" product="OpenSSH" version="7.4" conf="10">'
            "<cpe>cpe:/o:linux:linux_kernel</cpe>"
            "<cpe>cpe:/a:openbsd:openssh:7.4</cpe>"
            "</service></port></ports>"
            "</host></nmaprun>"
        )
        results = _parse_xml(xml)
        assert results[0].services[0].cpe == "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"
        # nmap's <service conf> attribute is captured as the match confidence.
        assert results[0].services[0].conf == 10

    def test_cpe_is_none_when_service_emits_no_cpe(self):
        # A service-name-only row (no -sV banner, no <cpe>) leaves cpe None.
        xml = (
            "<?xml version='1.0'?><nmaprun>"
            '<host><address addr="1.1.1.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22">'
            '<state state="open"/><service name="ssh"/></port></ports>'
            "</host></nmaprun>"
        )
        results = _parse_xml(xml)
        assert results[0].services[0].cpe is None

    def test_skips_port_with_non_numeric_portid(self):
        xml = (
            "<?xml version='1.0'?><nmaprun>"
            '<host><address addr="1.1.1.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="not-a-number">'
            '<state state="open"/></port></ports>'
            "</host></nmaprun>"
        )
        results = _parse_xml(xml)
        assert len(results) == 1
        assert results[0].services == []
