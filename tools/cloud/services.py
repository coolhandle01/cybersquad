"""
Exposed service checks: unauthenticated databases, sensitive files, admin panels, and
branded control panels / monitoring tools.

Each public function is a focused check that the Penetration Tester agent invokes
selectively based on nmap open_ports data and detected technologies.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse, urlunparse

from config import config
from models import AttackGraph, Endpoint, RawFinding, Severity
from tools import http
from tools.cloud.databases import (
    check_couchdb,
    check_elasticsearch,
    check_mongodb,
    check_mysql,
    check_postgresql,
    check_redis,
)

logger = logging.getLogger(__name__)

_SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    ("/.git/HEAD", "ref: refs/", "Git Repository Exposed"),
    ("/.env", "=", ".env File Exposed"),
    ("/phpinfo.php", "PHP Version", "phpinfo Exposed"),
    ("/server-status", "Apache", "Apache server-status Exposed"),
    ("/.DS_Store", "\x00\x00\x00\x01", "DS_Store File Exposed"),
]

_ADMIN_PATHS = [
    "/admin",
    "/admin/",
    "/wp-admin/",
    "/phpmyadmin/",
    "/adminer",
    "/adminer.php",
    "/manager/html",
    "/_admin",
]

_ADMIN_CONTENT_MARKERS = [
    "dashboard",
    "admin panel",
    "administration",
    "login",
    "sign in",
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _origin(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, "", "", "", ""))


def _unique_origins(endpoints: list[Endpoint]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for ep in endpoints:
        o = _origin(ep.url)
        if o not in seen:
            seen.add(o)
            result.append(o)
    return result


def _probe_panel(
    hostnames: list[str],
    scheme: str,
    port: int,
    path: str,
    marker: str,
    panel_name: str,
    tool_name: str,
) -> list[RawFinding]:
    """Probe a specific scheme/port/path on each hostname for panel content."""
    findings: list[RawFinding] = []
    for hostname in hostnames:
        url = f"{scheme}://{hostname}:{port}{path}"
        try:
            resp = http.get(  # nosemgrep
                url,
                timeout=5,
                verify=False,  # nosec B501
                allow_redirects=True,
            )
            if resp.status_code == 200 and marker.lower() in resp.text.lower():
                findings.append(
                    RawFinding(
                        title=f"Exposed {panel_name} - {url}",
                        vuln_class="ExposedAdminPanel",
                        target=url,
                        evidence=f"HTTP 200 with {panel_name} content at {url}",
                        tool=tool_name,
                        severity_hint=Severity.HIGH,
                    )
                )
        except Exception as exc:
            logger.debug("%s check failed for %s: %s", panel_name, url, exc)
    return findings


def _probe_path(
    origins: list[str],
    path: str,
    marker: str,
    panel_name: str,
    tool_name: str,
) -> list[RawFinding]:
    """Probe a path on existing origins as a reverse-proxy fallback."""
    findings: list[RawFinding] = []
    for origin in origins:
        target_url = origin + path
        try:
            resp = http.get(  # nosemgrep
                target_url,
                timeout=config.recon.http_timeout,
                allow_redirects=True,
            )
            if resp.status_code == 200 and marker.lower() in resp.text.lower():
                findings.append(
                    RawFinding(
                        title=f"Exposed {panel_name} - {target_url}",
                        vuln_class="ExposedAdminPanel",
                        target=target_url,
                        evidence=f"HTTP 200 with {panel_name} content at {target_url}",
                        tool=tool_name,
                        severity_hint=Severity.HIGH,
                    )
                )
        except Exception as exc:
            logger.debug("%s path check failed for %s: %s", panel_name, target_url, exc)
    return findings


# ---------------------------------------------------------------------------
# Public check functions
# ---------------------------------------------------------------------------


def check_unauthenticated_databases(recon: AttackGraph) -> list[RawFinding]:
    """Aggregate: run all per-engine database checks for hosts with matching open ports."""
    _port_checks = {
        9200: check_elasticsearch,
        5984: check_couchdb,
        6379: check_redis,
        27017: check_mongodb,
        5432: check_postgresql,
        3306: check_mysql,
    }
    findings: list[RawFinding] = []
    for host, ports in recon.open_ports.items():
        for port, fn in _port_checks.items():
            if port in ports:
                findings.extend(fn(host))
    logger.info("Unauthenticated databases check found %d findings", len(findings))
    return findings


def check_sensitive_files(endpoints: list[Endpoint]) -> list[RawFinding]:
    """Probe for exposed .git/HEAD, .env, phpinfo.php, server-status, and .DS_Store."""
    findings: list[RawFinding] = []
    for origin in _unique_origins(endpoints):
        for path, marker, title in _SENSITIVE_PATHS:
            target_url = origin + path
            try:
                resp = http.get(  # nosemgrep
                    target_url,
                    timeout=config.recon.http_timeout,
                    allow_redirects=False,
                )
                if resp.status_code == 200 and marker in resp.text:
                    findings.append(
                        RawFinding(
                            title=f"{title} - {target_url}",
                            vuln_class="SensitiveFileExposed",
                            target=target_url,
                            evidence=f"HTTP 200 - {resp.text[:300]}",
                            tool="sensitive_files_check",
                            severity_hint=Severity.HIGH,
                        )
                    )
            except Exception as exc:
                logger.debug("Sensitive file check failed for %s: %s", target_url, exc)
    logger.info("Sensitive files check found %d findings", len(findings))
    return findings


def check_admin_panels(endpoints: list[Endpoint]) -> list[RawFinding]:
    """Probe common admin panel paths (/admin, /wp-admin, /phpmyadmin, etc.)."""
    findings: list[RawFinding] = []
    for origin in _unique_origins(endpoints):
        for path in _ADMIN_PATHS:
            target_url = origin + path
            try:
                resp = http.get(  # nosemgrep
                    target_url,
                    timeout=config.recon.http_timeout,
                    allow_redirects=False,
                )
                if resp.status_code == 200:
                    body_lower = resp.text[:1000].lower()
                    if any(m in body_lower for m in _ADMIN_CONTENT_MARKERS):
                        findings.append(
                            RawFinding(
                                title=f"Exposed Admin Panel - {target_url}",
                                vuln_class="ExposedAdminPanel",
                                target=target_url,
                                evidence=(f"HTTP 200 with admin-related content at {target_url}"),
                                tool="admin_panels_check",
                                severity_hint=Severity.HIGH,
                            )
                        )
            except Exception as exc:
                logger.debug("Admin panel check failed for %s: %s", target_url, exc)
    logger.info("Admin panels check found %d findings", len(findings))
    return findings


def check_cpanel(hostnames: list[str]) -> list[RawFinding]:
    """Check for exposed cPanel (ports 2082/2083) and WHM (ports 2086/2087)."""
    findings: list[RawFinding] = []
    for scheme, port, marker, label in [
        ("http", 2082, "cPanel", "cPanel"),
        ("https", 2083, "cPanel", "cPanel"),
        ("http", 2086, "WebHost Manager", "WHM"),
        ("https", 2087, "WebHost Manager", "WHM"),
    ]:
        findings.extend(_probe_panel(hostnames, scheme, port, "/", marker, label, "cpanel_check"))
    logger.info("cPanel/WHM check found %d findings", len(findings))
    return findings


def check_plesk(hostnames: list[str]) -> list[RawFinding]:
    """Check for an exposed Plesk control panel (ports 8880/8443)."""
    findings = _probe_panel(hostnames, "http", 8880, "/", "Plesk", "Plesk", "plesk_check")
    findings += _probe_panel(
        hostnames, "https", 8443, "/login.php", "Plesk", "Plesk", "plesk_check"
    )
    logger.info("Plesk check found %d findings", len(findings))
    return findings


def check_directadmin(hostnames: list[str]) -> list[RawFinding]:
    """Check for an exposed DirectAdmin control panel (port 2222)."""
    findings = _probe_panel(
        hostnames, "http", 2222, "/login.php", "DirectAdmin", "DirectAdmin", "directadmin_check"
    )
    logger.info("DirectAdmin check found %d findings", len(findings))
    return findings


def check_webmin(hostnames: list[str]) -> list[RawFinding]:
    """Check for an exposed Webmin administration panel (port 10000)."""
    findings = _probe_panel(hostnames, "https", 10000, "/", "Webmin", "Webmin", "webmin_check")
    logger.info("Webmin check found %d findings", len(findings))
    return findings


def check_grafana_ports(hostnames: list[str]) -> list[RawFinding]:
    """Check for an exposed Grafana instance on port 3000."""
    findings = _probe_panel(hostnames, "http", 3000, "/", "Grafana", "Grafana", "grafana_check")
    logger.info("Grafana port check found %d findings", len(findings))
    return findings


def check_grafana_paths(endpoints: list[Endpoint]) -> list[RawFinding]:
    """Check for Grafana reverse-proxied at /grafana on existing endpoints."""
    findings = _probe_path(
        _unique_origins(endpoints), "/grafana", "Grafana", "Grafana", "grafana_check"
    )
    logger.info("Grafana path check found %d findings", len(findings))
    return findings


def check_kibana_ports(hostnames: list[str]) -> list[RawFinding]:
    """Check for an exposed Kibana instance on port 5601."""
    findings = _probe_panel(hostnames, "http", 5601, "/", "Kibana", "Kibana", "kibana_check")
    logger.info("Kibana port check found %d findings", len(findings))
    return findings


def check_kibana_paths(endpoints: list[Endpoint]) -> list[RawFinding]:
    """Check for Kibana reverse-proxied at /kibana on existing endpoints."""
    findings = _probe_path(
        _unique_origins(endpoints), "/kibana", "Kibana", "Kibana", "kibana_check"
    )
    logger.info("Kibana path check found %d findings", len(findings))
    return findings


def check_portainer_ports(hostnames: list[str]) -> list[RawFinding]:
    """Check for an exposed Portainer Docker management UI on port 9000."""
    findings = _probe_panel(
        hostnames, "http", 9000, "/", "Portainer", "Portainer", "portainer_check"
    )
    logger.info("Portainer port check found %d findings", len(findings))
    return findings


def check_portainer_paths(endpoints: list[Endpoint]) -> list[RawFinding]:
    """Check for Portainer reverse-proxied at /portainer on existing endpoints."""
    findings = _probe_path(
        _unique_origins(endpoints), "/portainer", "Portainer", "Portainer", "portainer_check"
    )
    logger.info("Portainer path check found %d findings", len(findings))
    return findings


def check_consul_vault_ports(hostnames: list[str]) -> list[RawFinding]:
    """Check for exposed Consul UI (port 8500) and Vault UI (port 8200)."""
    findings = _probe_panel(
        hostnames, "http", 8500, "/ui/", "Consul", "Consul", "consul_vault_check"
    )
    findings += _probe_panel(
        hostnames, "http", 8200, "/ui/", "Vault", "Vault", "consul_vault_check"
    )
    logger.info("Consul/Vault port check found %d findings", len(findings))
    return findings


def check_consul_vault_paths(endpoints: list[Endpoint]) -> list[RawFinding]:
    """Check for Consul / Vault reverse-proxied at /consul/ui or /vault/ui."""
    origins = _unique_origins(endpoints)
    findings = _probe_path(origins, "/consul/ui", "Consul", "Consul", "consul_vault_check")
    findings += _probe_path(origins, "/vault/ui", "Vault", "Vault", "consul_vault_check")
    logger.info("Consul/Vault path check found %d findings", len(findings))
    return findings
