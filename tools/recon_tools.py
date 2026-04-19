"""
tools/recon_tools.py — OSINT and reconnaissance tooling for the OSINT Analyst.

Wraps external binaries (subfinder, httpx, nmap) and pure-Python helpers.

External dependencies (install separately):
    subfinder   https://github.com/projectdiscovery/subfinder
    httpx       https://github.com/projectdiscovery/httpx  (CLI, not the Python lib)
    nmap        https://nmap.org
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from urllib.parse import urlparse

from config import config
from models import Endpoint, Programme, ReconResult, ScopeType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_binary(name: str) -> str:
    """Return full path to a binary or raise if not found."""
    path = shutil.which(name)
    if not path:
        raise OSError(
            f"Required binary '{name}' not found in PATH. "
            f"Please install it before running the pipeline."
        )
    return path


def _run(
    cmd: list[str],
    timeout: int = 120,
    input: str | None = None,  # noqa: A002
) -> subprocess.CompletedProcess:
    """Run a subprocess, log stderr, return CompletedProcess."""
    logger.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input,
    )
    if result.returncode != 0:
        logger.warning("Command exited %d: %s", result.returncode, result.stderr[:500])
    return result


# ---------------------------------------------------------------------------
# Subdomain enumeration
# ---------------------------------------------------------------------------


def enumerate_subdomains(domain: str) -> list[str]:
    """
    Use subfinder to enumerate subdomains for *domain*.
    Returns a deduplicated list of discovered hostnames.
    """
    subfinder = _require_binary("subfinder")
    result = _run(
        [subfinder, "-d", domain, "-silent", "-o", "/dev/stdout"],
        timeout=180,
    )
    subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    logger.info("subfinder found %d subdomains for %s", len(subdomains), domain)
    return list(dict.fromkeys(subdomains))[: config.recon.max_subdomains]


# ---------------------------------------------------------------------------
# HTTP probing
# ---------------------------------------------------------------------------


def probe_endpoints(hosts: list[str]) -> list[Endpoint]:
    """
    Use httpx CLI to probe a list of hostnames/URLs.
    Returns Endpoint objects with status codes and detected technologies.
    """
    httpx_bin = _require_binary("httpx")
    # FIX: input_data was computed but never passed — httpx received no targets
    input_data = "\n".join(hosts)

    result = _run(
        [
            httpx_bin,
            "-silent",
            "-json",
            "-status-code",
            "-tech-detect",
            "-timeout",
            str(config.recon.http_timeout),
        ],
        timeout=300,
        input=input_data,
    )

    endpoints: list[Endpoint] = []
    for line in result.stdout.splitlines():
        try:
            entry = json.loads(line)
            endpoints.append(
                Endpoint(
                    url=entry.get("url", ""),
                    status_code=entry.get("status_code"),
                    technologies=entry.get("tech", []),
                )
            )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.debug("Skipping httpx line: %s (%s)", line[:80], exc)

    logger.info("httpx probed %d live endpoints from %d hosts", len(endpoints), len(hosts))
    return endpoints


# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------


def port_scan(hosts: list[str]) -> dict[str, list[int]]:
    """
    Run a lightweight nmap TCP SYN scan on common ports.
    Returns {host: [open_ports]}.
    """
    nmap = _require_binary("nmap")
    results: dict[str, list[int]] = {}

    for host in hosts:
        result = _run(
            [nmap, "-sS", "--open", "-T4", "-F", "-oG", "-", host],
            timeout=60,
        )
        open_ports: list[int] = []
        for line in result.stdout.splitlines():
            if "Ports:" in line:
                for token in line.split():
                    if "/open/" in token:
                        try:
                            open_ports.append(int(token.split("/")[0]))
                        except ValueError:
                            pass
        results[host] = open_ports
        logger.info("nmap: %s → %s", host, open_ports)

    return results


# ---------------------------------------------------------------------------
# Scope guard
# ---------------------------------------------------------------------------


def extract_domain(identifier: str) -> str:
    """Pull the registrable domain out of a URL or hostname."""
    parsed = urlparse(identifier if "://" in identifier else f"http://{identifier}")
    return parsed.hostname or identifier


def filter_in_scope(hosts: list[str], programme: Programme) -> list[str]:
    """
    Return only hosts that fall within the programme's declared in-scope assets.
    Wildcards (*.example.com) are matched against subdomains.
    """
    allowed: list[str] = []
    for host in hosts:
        for scope_item in programme.in_scope:
            if scope_item.asset_type not in (ScopeType.URL, ScopeType.WILDCARD):
                continue
            pattern = scope_item.asset_identifier.lstrip("*.")
            # FIX: bare endswith(pattern) allowed evil.notexample.com to match
            # example.com — must verify a dot boundary or exact match
            if host == pattern or host.endswith("." + pattern):
                allowed.append(host)
                break
    logger.info(
        "Scope filter: %d/%d hosts in scope for %s",
        len(allowed),
        len(hosts),
        programme.handle,
    )
    return allowed


# ---------------------------------------------------------------------------
# Orchestration — called by the OSINT Analyst agent task
# ---------------------------------------------------------------------------


def run_recon(programme: Programme) -> ReconResult:
    """
    Full recon pipeline for a single programme.
    Extracts domains from scope, enumerates subdomains, probes HTTP, scans ports.
    """
    seed_domains: list[str] = [
        extract_domain(item.asset_identifier)
        for item in programme.in_scope
        if item.asset_type in (ScopeType.URL, ScopeType.WILDCARD)
    ]
    seed_domains = list(dict.fromkeys(seed_domains))

    all_subdomains: list[str] = []
    for domain in seed_domains:
        all_subdomains.extend(enumerate_subdomains(domain))

    in_scope_hosts = filter_in_scope(all_subdomains, programme)

    endpoints = probe_endpoints(in_scope_hosts)

    live_hosts = [ep.url for ep in endpoints if ep.status_code and ep.status_code < 500]
    open_ports = port_scan(live_hosts[:20])

    all_tech: list[str] = []
    for ep in endpoints:
        all_tech.extend(ep.technologies)
    unique_tech = list(dict.fromkeys(all_tech))

    return ReconResult(
        programme=programme,
        subdomains=in_scope_hosts,
        endpoints=endpoints,
        open_ports=open_ports,
        technologies=unique_tech,
        notes=f"Seeded from {seed_domains}. {len(in_scope_hosts)} in-scope hosts.",
    )
