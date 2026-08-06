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

    def test_dispatches_postgresql_on_5432(self, programme):
        # 5432 -> check_postgresql must be wired: without a test here the
        # port-map entry can be mutated (5432 -> 5433) undetected.
        recon = AttackGraph(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"db.example.com": [5432]},
            technologies=[],
        )
        # PostgreSQL AuthenticationOk with method 0 (trust auth).
        pg_trust = b"R" + (8).to_bytes(4, "big") + (0).to_bytes(4, "big")
        mock_sock = MagicMock()
        mock_sock.recv.return_value = pg_trust
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch("tools.cloud.databases.sql.socket.create_connection", return_value=mock_sock):
            results = check_unauthenticated_databases(recon)
        pg = [r for r in results if "PostgreSQL" in r.title]
        assert len(pg) == 1
        assert pg[0].severity_hint == Severity.CRITICAL

    def test_dispatches_mysql_on_3306(self, programme):
        # 3306 -> check_mysql must be wired (guards against 3306 -> 3307).
        recon = AttackGraph(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"db.example.com": [3306]},
            technologies=[],
        )
        version = b"8.0.28\x00"
        payload = b"\x0a" + version + b"\x00" * 20
        greeting = len(payload).to_bytes(3, "little") + b"\x00" + payload
        mock_sock = MagicMock()
        mock_sock.recv.return_value = greeting
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch("tools.cloud.databases.sql.socket.create_connection", return_value=mock_sock):
            results = check_unauthenticated_databases(recon)
        mysql = [r for r in results if "MySQL" in r.title]
        assert len(mysql) == 1

    def test_passes_the_actual_host_to_each_check(self, programme):
        # The dispatched check must receive the real host, not a placeholder:
        # the finding's target has to carry that host through.
        recon = AttackGraph(
            programme=programme,
            subdomains=[],
            endpoints=[],
            open_ports={"es.example.com": [9200]},
            technologies=[],
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"cluster_name":"prod"}'
        with patch("requests.get", return_value=mock_resp):
            results = check_unauthenticated_databases(recon)
        es = [r for r in results if "Elasticsearch" in r.title]
        assert len(es) == 1
        assert es[0].target == "http://es.example.com:9200/_cluster/health"

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

    def test_no_finding_when_status_200_but_marker_absent(self, target_apex):
        # A path that returns 200 but whose body lacks the file's signature
        # marker is not an exposure (e.g. a SPA catch-all serving index.html
        # for /.git/HEAD). Guard is status AND marker; kills and->or.
        def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "<html><body>Not Found</body></html>"  # no marker
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_sensitive_files(self._make_eps(target_apex))
        assert results == []

    def test_finding_fields_and_exact_probe_target(self, target_apex):
        # Endpoint carries a path/query/fragment: the probe must target the
        # bare origin + sensitive path (proving _origin strips path/params/
        # query/fragment), and the finding fields are pinned exactly. The
        # long body pins the evidence [:300] excerpt.
        endpoint = Endpoint(
            url=f"https://app.{target_apex}/dashboard/index?tab=1#top", status_code=200
        )
        body = "ref: refs/heads/main\n" + "x" * 400

        def fake_get(url, **kwargs):
            resp = MagicMock()
            if url.endswith("/.git/HEAD"):
                resp.status_code = 200
                resp.text = body
                assert kwargs["allow_redirects"] is False
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_sensitive_files([endpoint])

        git = [r for r in results if "Git Repository" in r.title]
        assert len(git) == 1
        f = git[0]
        assert f.target == f"https://app.{target_apex}/.git/HEAD"
        assert f.title == f"Git Repository Exposed - https://app.{target_apex}/.git/HEAD"
        assert f.vuln_class == "SensitiveFileExposed"
        assert f.tool == "sensitive_files_check"
        assert f.severity_hint == Severity.HIGH
        assert f.evidence == f"HTTP 200 - {body[:300]}"

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

    def test_no_finding_when_200_but_no_admin_marker(self, target_apex, clean_response_body):
        # A 200 whose body carries none of the admin-content markers is not
        # an admin panel. The detection is any(marker in body); kills the
        # any(marker not in body) inversion, which would fire on clean pages.
        def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = clean_response_body
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_admin_panels(self._make_eps(target_apex))
        assert results == []

    def test_marker_beyond_1000_char_window_is_not_detected(self, target_apex):
        # Admin-content markers are scanned only within the first 1000 chars
        # of the body. A "login" marker whose last character sits at index
        # 1000 is outside body[:1000] but inside body[:1001] - pins the exact
        # scan-window boundary (kills the [:1000] -> [:1001] mutation).
        body = "x" * 996 + "login" + "x" * 8  # 'login' occupies indices 996..1000

        def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = body
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_admin_panels(self._make_eps(target_apex))
        assert results == []

    def test_finding_fields_and_call_args(self, target_apex):
        captured: dict = {}

        def fake_get(url, **kwargs):
            resp = MagicMock()
            if url == f"https://app.{target_apex}/admin":
                captured["kwargs"] = kwargs
                resp.status_code = 200
                resp.text = "<html><h1>Admin Dashboard</h1><a>Login</a></html>"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = check_admin_panels(self._make_eps(target_apex))

        assert captured["kwargs"]["allow_redirects"] is False
        panels = [r for r in results if r.target == f"https://app.{target_apex}/admin"]
        assert len(panels) == 1
        f = panels[0]
        assert f.title == f"Exposed Admin Panel - https://app.{target_apex}/admin"
        assert f.vuln_class == "ExposedAdminPanel"
        assert f.tool == "admin_panels_check"
        assert f.severity_hint == Severity.HIGH
        assert (
            f.evidence == f"HTTP 200 with admin-related content at https://app.{target_apex}/admin"
        )

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


# One row per underlying probe call a branded wrapper makes. Each row is the
# full (scheme, port, path, marker, panel_name, tool_name) tuple the wrapper
# passes down: pinning the resulting finding to the exact URL / title /
# evidence / tool proves each constant reaches the probe intact (a mutated
# port, path, panel-name or tool-name changes an asserted field), and the
# marker-gated mock means a mutated marker yields no finding at all.
_PORT_WRAPPER_CALLS = [
    (check_cpanel, "http", 2082, "/", "cPanel", "cPanel", "cpanel_check"),
    (check_cpanel, "https", 2083, "/", "cPanel", "cPanel", "cpanel_check"),
    (check_cpanel, "http", 2086, "/", "WebHost Manager", "WHM", "cpanel_check"),
    (check_cpanel, "https", 2087, "/", "WebHost Manager", "WHM", "cpanel_check"),
    (check_plesk, "http", 8880, "/", "Plesk", "Plesk", "plesk_check"),
    (check_plesk, "https", 8443, "/login.php", "Plesk", "Plesk", "plesk_check"),
    (
        check_directadmin,
        "http",
        2222,
        "/login.php",
        "DirectAdmin",
        "DirectAdmin",
        "directadmin_check",
    ),
    (check_webmin, "https", 10000, "/", "Webmin", "Webmin", "webmin_check"),
    (check_grafana_ports, "http", 3000, "/", "Grafana", "Grafana", "grafana_check"),
    (check_kibana_ports, "http", 5601, "/", "Kibana", "Kibana", "kibana_check"),
    (check_portainer_ports, "http", 9000, "/", "Portainer", "Portainer", "portainer_check"),
    (check_consul_vault_ports, "http", 8500, "/ui/", "Consul", "Consul", "consul_vault_check"),
    (check_consul_vault_ports, "http", 8200, "/ui/", "Vault", "Vault", "consul_vault_check"),
]

_PATH_WRAPPER_CALLS = [
    (check_grafana_paths, "/grafana", "Grafana", "Grafana", "grafana_check"),
    (check_kibana_paths, "/kibana", "Kibana", "Kibana", "kibana_check"),
    (check_portainer_paths, "/portainer", "Portainer", "Portainer", "portainer_check"),
    (check_consul_vault_paths, "/consul/ui", "Consul", "Consul", "consul_vault_check"),
    (check_consul_vault_paths, "/vault/ui", "Vault", "Vault", "consul_vault_check"),
]


class TestProbeHelperContracts:
    """The shared _probe_panel / _probe_path helpers reached through their
    real wrappers - pinning the outbound call args, the status+marker guard,
    and the finding shape each wrapper's constants produce."""

    def _host(self, target_apex: str) -> str:
        return f"app.{target_apex}"

    def _endpoints(self, target_apex: str) -> list[Endpoint]:
        return [Endpoint(url=f"https://app.{target_apex}/", status_code=200)]

    def test_probe_panel_call_args(self, target_apex):
        # check_webmin makes a single _probe_panel call (https:10000/).
        host = self._host(target_apex)
        expected_url = f"https://{host}:10000/"
        captured: dict = {}

        def fake_get(url, **kwargs):
            resp = MagicMock()
            if url == expected_url:
                captured["kwargs"] = kwargs
                resp.status_code = 200
                resp.text = "<html>Webmin</html>"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        with patch("requests.get", side_effect=fake_get):
            check_webmin([host])

        kwargs = captured["kwargs"]
        assert kwargs["timeout"] == 5
        assert kwargs["verify"] is False
        assert kwargs["allow_redirects"] is True

    def test_probe_panel_no_finding_when_marker_absent(self, target_apex, clean_response_body):
        # 200 on the panel port but no product marker in the body -> no
        # finding. Kills the and->or on the _probe_panel guard.
        def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = clean_response_body
            return resp

        with patch("requests.get", side_effect=fake_get):
            assert check_webmin([self._host(target_apex)]) == []

    def test_probe_path_call_args(self, target_apex):
        # check_grafana_paths makes a single _probe_path call (/grafana).
        expected_url = f"https://app.{target_apex}/grafana"
        captured: dict = {}

        def fake_get(url, **kwargs):
            resp = MagicMock()
            if url == expected_url:
                captured["kwargs"] = kwargs
                resp.status_code = 200
                resp.text = "<html>Grafana</html>"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        with patch("requests.get", side_effect=fake_get):
            check_grafana_paths(self._endpoints(target_apex))

        kwargs = captured["kwargs"]
        assert kwargs["timeout"] == 10
        assert kwargs["allow_redirects"] is True

    def test_probe_path_no_finding_when_marker_absent(self, target_apex, clean_response_body):
        # 200 at /grafana but no marker in the body -> no finding. Kills the
        # and->or on the _probe_path guard.
        def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = clean_response_body
            return resp

        with patch("requests.get", side_effect=fake_get):
            assert check_grafana_paths(self._endpoints(target_apex)) == []

    @pytest.mark.parametrize(
        "fn,scheme,port,path,marker,panel_name,tool_name",
        _PORT_WRAPPER_CALLS,
        ids=[f"{r[0].__name__}-{r[2]}" for r in _PORT_WRAPPER_CALLS],
    )
    def test_port_wrapper_finding_is_fully_pinned(
        self, target_apex, fn, scheme, port, path, marker, panel_name, tool_name
    ):
        host = self._host(target_apex)
        expected_url = f"{scheme}://{host}:{port}{path}"

        def fake_get(url, **kwargs):
            resp = MagicMock()
            if url == expected_url:
                resp.status_code = 200
                resp.text = f"<html>{marker} control panel</html>"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = fn([host])

        assert len(results) == 1
        f = results[0]
        assert f.target == expected_url
        assert f.title == f"Exposed {panel_name} - {expected_url}"
        assert f.evidence == f"HTTP 200 with {panel_name} content at {expected_url}"
        assert f.tool == tool_name
        assert f.vuln_class == "ExposedAdminPanel"
        assert f.severity_hint == Severity.HIGH

    @pytest.mark.parametrize(
        "fn,path,marker,panel_name,tool_name",
        _PATH_WRAPPER_CALLS,
        ids=[f"{r[0].__name__}-{r[1].strip('/').replace('/', '_')}" for r in _PATH_WRAPPER_CALLS],
    )
    def test_path_wrapper_finding_is_fully_pinned(
        self, target_apex, fn, path, marker, panel_name, tool_name
    ):
        expected_url = f"https://app.{target_apex}{path}"

        def fake_get(url, **kwargs):
            resp = MagicMock()
            if url == expected_url:
                resp.status_code = 200
                resp.text = f"<html>{marker} dashboard</html>"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        with patch("requests.get", side_effect=fake_get):
            results = fn(self._endpoints(target_apex))

        assert len(results) == 1
        f = results[0]
        assert f.target == expected_url
        assert f.title == f"Exposed {panel_name} - {expected_url}"
        assert f.evidence == f"HTTP 200 with {panel_name} content at {expected_url}"
        assert f.tool == tool_name
        assert f.vuln_class == "ExposedAdminPanel"
        assert f.severity_hint == Severity.HIGH
