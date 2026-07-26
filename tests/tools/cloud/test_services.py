"""tests/tools/cloud/test_services.py - unit tests for tools/cloud/services.py.

Exposed-service checks: unauthenticated databases (Elasticsearch / CouchDB
/ Redis / MongoDB), sensitive-file exposure (.git / .env / phpinfo / ...),
admin panels, and the per-product branded panel / dashboard probes
(cPanel / Plesk / Grafana / Kibana / Portainer / Consul / Vault).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import AttackGraph, Endpoint, Severity
from tools.cloud.services import (
    check_admin_panels,
    check_consul_vault_paths,
    check_consul_vault_ports,
    check_cpanel,
    check_directadmin,
    check_grafana_paths,
    check_grafana_ports,
    check_kibana_paths,
    check_kibana_ports,
    check_plesk,
    check_portainer_paths,
    check_portainer_ports,
    check_sensitive_files,
    check_unauthenticated_databases,
    check_webmin,
)

pytestmark = pytest.mark.unit


class TestCheckUnauthenticatedDatabases:
    def test_detects_elasticsearch(self, programme):
        recon = AttackGraph(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"es.example.com": [9200]},
            technologies=[],
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"cluster_name":"prod","status":"green"}'
        with patch("requests.get", return_value=mock_resp):
            results = check_unauthenticated_databases(recon)
        es = [r for r in results if "Elasticsearch" in r.title]
        assert len(es) == 1
        assert es[0].severity_hint == Severity.CRITICAL
        assert es[0].vuln_class == "ExposedService"

    def test_detects_couchdb(self, programme):
        recon = AttackGraph(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"db.example.com": [5984]},
            technologies=[],
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '["_users","mydb"]'
        with patch("requests.get", return_value=mock_resp):
            results = check_unauthenticated_databases(recon)
        couch = [r for r in results if "CouchDB" in r.title]
        assert len(couch) == 1
        assert couch[0].severity_hint == Severity.CRITICAL

    def test_detects_redis_via_ping(self, programme):
        recon = AttackGraph(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"cache.example.com": [6379]},
            technologies=[],
        )
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"+PONG\r\n"
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch("tools.cloud.databases.redis.socket.create_connection", return_value=mock_sock):
            results = check_unauthenticated_databases(recon)
        redis = [r for r in results if "Redis" in r.title]
        assert len(redis) == 1
        assert redis[0].severity_hint == Severity.CRITICAL

    def test_detects_mongodb_via_ismaster(self, programme):
        recon = AttackGraph(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"mongo.example.com": [27017]},
            technologies=[],
        )
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x00" * 20 + b"ismaster" + b"\x00" * 10
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch(
            "tools.cloud.databases.mongodb.socket.create_connection", return_value=mock_sock
        ):
            results = check_unauthenticated_databases(recon)
        mongo = [r for r in results if "MongoDB" in r.title]
        assert len(mongo) == 1
        assert mongo[0].severity_hint == Severity.CRITICAL

    def test_skips_host_without_matching_ports(self, programme):
        recon = AttackGraph(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"host.example.com": [80, 443]},
            technologies=[],
        )
        with patch("requests.get") as mock_get:
            results = check_unauthenticated_databases(recon)
        mock_get.assert_not_called()
        assert results == []

    def test_exception_is_swallowed(self, programme):
        recon = AttackGraph(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"host.example.com": [9200]},
            technologies=[],
        )
        with patch("requests.get", side_effect=Exception("refused")):
            results = check_unauthenticated_databases(recon)
        assert results == []


class TestCheckSensitiveFiles:
    def _make_eps(self, target_apex):
        return [Endpoint(url=f"https://app.{target_apex}/", status_code=200)]

    def test_detects_git_head(self, target_apex):
        def fake_get(url, **kwargs):
            resp = MagicMock()
            if "/.git/HEAD" in url:
                resp.status_code = 200
                resp.text = "ref: refs/heads/main\n"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_sensitive_files(self._make_eps(target_apex))
        git = [r for r in results if "Git Repository" in r.title]
        assert len(git) == 1
        assert git[0].severity_hint == Severity.HIGH
        assert git[0].vuln_class == "SensitiveFileExposed"

    def test_detects_env_file(self, target_apex):
        def fake_get(url, **kwargs):
            resp = MagicMock()
            if "/.env" in url and "git" not in url:
                resp.status_code = 200
                resp.text = "APP_KEY=abc\nDB_PASSWORD=secret\n"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_sensitive_files(self._make_eps(target_apex))
        env = [r for r in results if ".env File" in r.title]
        assert len(env) == 1

    def test_deduplicates_by_origin(self, target_url: str):
        endpoints = [
            Endpoint(url=f"{target_url}/page1", status_code=200),
            Endpoint(url=f"{target_url}/page2", status_code=200),
        ]
        call_count = 0

        def counting_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.status_code = 404
            resp.text = ""
            return resp

        with patch("requests.get", side_effect=counting_get):
            check_sensitive_files(endpoints)

        # Only one origin, so paths are probed once each
        assert call_count == len(
            ["/.git/HEAD", "/.env", "/phpinfo.php", "/server-status", "/.DS_Store"]
        )

    def test_exception_is_swallowed(self, target_apex):
        with patch("requests.get", side_effect=Exception("timeout")):
            results = check_sensitive_files(self._make_eps(target_apex))
        assert results == []


class TestCheckAdminPanels:
    def _make_eps(self, target_apex):
        return [Endpoint(url=f"https://app.{target_apex}/", status_code=200)]

    def test_detects_admin_panel(self, target_apex):
        def fake_get(url, **kwargs):
            resp = MagicMock()
            if "/admin" in url:
                resp.status_code = 200
                resp.text = "<html><h1>Admin Dashboard</h1></html>"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_admin_panels(self._make_eps(target_apex))
        panels = [r for r in results if "Admin Panel" in r.title]
        assert len(panels) >= 1
        assert panels[0].severity_hint == Severity.HIGH
        assert panels[0].vuln_class == "ExposedAdminPanel"

    def test_no_finding_for_404(self, target_apex):
        def always_404(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            resp.text = ""
            return resp

        with patch("requests.get", side_effect=always_404):
            results = check_admin_panels(self._make_eps(target_apex))
        assert results == []

    def test_exception_is_swallowed(self, target_apex):
        with patch("requests.get", side_effect=Exception("refused")):
            results = check_admin_panels(self._make_eps(target_apex))
        assert results == []


class TestGranularPanels:
    """Spot-check each branded panel / dashboard tool hits the right
    port (or reverse-proxy path) on the right host. Helpers now take
    typed inputs (``list[str]`` for hostnames, ``list[Endpoint]`` for
    path probes) rather than ``AttackGraph``; the conversion lives at
    the wrapper layer."""

    def _hostnames(self, target_apex: str) -> list[str]:
        return [f"app.{target_apex}"]

    def _endpoints(self, target_apex: str) -> list[Endpoint]:
        return [Endpoint(url=f"https://app.{target_apex}/", status_code=200)]

    def _port_mock(self, port: int, marker: str, make_response):
        from urllib.parse import urlparse as _up

        def fake_get(url, **kwargs):
            parsed = _up(url)
            if parsed.port == port:
                return make_response(status=200, body=f"<html>{marker}</html>")
            return make_response(status=404, body="")

        return fake_get

    def test_cpanel_port_2083(self, target_apex, make_response):
        with patch("requests.get", side_effect=self._port_mock(2083, "cPanel", make_response)):
            results = check_cpanel(self._hostnames(target_apex))
        assert any("cPanel" in r.title for r in results)

    def test_whm_port_2087(self, target_apex, make_response):
        with patch(
            "requests.get", side_effect=self._port_mock(2087, "WebHost Manager", make_response)
        ):
            results = check_cpanel(self._hostnames(target_apex))
        assert any("WHM" in r.title for r in results)

    def test_plesk_port_8443(self, target_apex, make_response):
        with patch("requests.get", side_effect=self._port_mock(8443, "Plesk", make_response)):
            results = check_plesk(self._hostnames(target_apex))
        assert any("Plesk" in r.title for r in results)

    def test_directadmin_port_2222(self, target_apex, make_response):
        with patch("requests.get", side_effect=self._port_mock(2222, "DirectAdmin", make_response)):
            results = check_directadmin(self._hostnames(target_apex))
        assert any("DirectAdmin" in r.title for r in results)

    def test_webmin_port_10000(self, target_apex, make_response):
        with patch("requests.get", side_effect=self._port_mock(10000, "Webmin", make_response)):
            results = check_webmin(self._hostnames(target_apex))
        assert any("Webmin" in r.title for r in results)

    def test_grafana_port_3000(self, target_apex, make_response):
        with patch("requests.get", side_effect=self._port_mock(3000, "Grafana", make_response)):
            results = check_grafana_ports(self._hostnames(target_apex))
        assert any("Grafana" in r.title for r in results)

    def test_kibana_port_5601(self, target_apex, make_response):
        with patch("requests.get", side_effect=self._port_mock(5601, "Kibana", make_response)):
            results = check_kibana_ports(self._hostnames(target_apex))
        assert any("Kibana" in r.title for r in results)

    def test_portainer_port_9000(self, target_apex, make_response):
        with patch("requests.get", side_effect=self._port_mock(9000, "Portainer", make_response)):
            results = check_portainer_ports(self._hostnames(target_apex))
        assert any("Portainer" in r.title for r in results)

    def test_consul_port_8500(self, target_apex, make_response):
        with patch("requests.get", side_effect=self._port_mock(8500, "Consul", make_response)):
            results = check_consul_vault_ports(self._hostnames(target_apex))
        assert any("Consul" in r.title for r in results)

    def test_vault_port_8200(self, target_apex, make_response):
        with patch("requests.get", side_effect=self._port_mock(8200, "Vault", make_response)):
            results = check_consul_vault_ports(self._hostnames(target_apex))
        assert any("Vault" in r.title for r in results)

    def test_grafana_path_probe(self, target_apex, make_response):
        """Grafana path check probes /grafana on supplied origins."""

        def fake_get(url, **kwargs):
            if url.endswith("/grafana"):
                return make_response(status=200, body="<html>Grafana dashboard</html>")
            return make_response(status=404, body="")

        with patch("requests.get", side_effect=fake_get):
            results = check_grafana_paths(self._endpoints(target_apex))
        assert any("Grafana" in r.title for r in results)

    def test_no_finding_when_all_404(self, target_apex):
        def always_404(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            resp.text = ""
            return resp

        hostnames = self._hostnames(target_apex)
        endpoints = self._endpoints(target_apex)
        with patch("requests.get", side_effect=always_404):
            for fn in (
                check_cpanel,
                check_plesk,
                check_directadmin,
                check_webmin,
                check_grafana_ports,
                check_kibana_ports,
                check_portainer_ports,
                check_consul_vault_ports,
            ):
                assert fn(hostnames) == []
            for fn in (
                check_grafana_paths,
                check_kibana_paths,
                check_portainer_paths,
                check_consul_vault_paths,
            ):
                assert fn(endpoints) == []

    def test_exception_is_swallowed(self, target_apex):
        hostnames = self._hostnames(target_apex)
        endpoints = self._endpoints(target_apex)
        with patch("requests.get", side_effect=Exception("refused")):
            for fn in (
                check_cpanel,
                check_plesk,
                check_directadmin,
                check_webmin,
                check_grafana_ports,
                check_kibana_ports,
                check_portainer_ports,
                check_consul_vault_ports,
            ):
                assert fn(hostnames) == []
            for fn in (
                check_grafana_paths,
                check_kibana_paths,
                check_portainer_paths,
                check_consul_vault_paths,
            ):
                assert fn(endpoints) == []
