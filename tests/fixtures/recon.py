"""Recon-shaped fixtures: ``Endpoint`` / ``AttackGraph`` plus the
cloud-storage hostname factories.

Bucket / container names are built from ``target_sld`` (the
second-level domain of ``target_apex``) so flipping ``target_url``
propagates through every cloud-storage test the same way it does for
every other in-scope-target literal. Factories rather than single
values where tests need variants (the "iterate every supplied
hostname" tests pass two distinct ones); single-value fixtures wrap
the factory at its canonical suffix for the common case. Mirrors the
``make_html_page`` pattern in ``domains.py``.

Loaded via ``pytest_plugins`` in ``tests/conftest.py``.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from models import AttackGraph, Endpoint, HostInsight, HostPriority, HostRole


@pytest.fixture()
def nmap_xml_two_hosts() -> str:
    """Real-shape nmap ``-oX`` output: two IPv4 hosts, banners on the first
    (http/nginx, ssh/OpenSSH), a bare redis service on the second."""
    return """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.6p1" extrainfo="Ubuntu"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="93.184.216.35" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.fixture()
def nmap_xml_no_hosts() -> str:
    """nmap ``-oX`` output with zero hosts (host down / nothing matched)."""
    return '<?xml version="1.0"?>\n<nmaprun></nmaprun>\n'


@pytest.fixture()
def make_host_insight(target_apex: str) -> Callable[..., HostInsight]:
    """Factory for a well-formed ``HostInsight`` (api.<apex>, HIGH, valid notes).

    ``make_host_insight()`` -> the canonical in-scope insight;
    ``make_host_insight(hostname=f"admin.{target_apex}", priority=...)`` for
    variants. Shared so the recon_insights / recon_host_store suites build
    one insight instead of each redefining a local ``_good_insight``.
    """

    def _make(**overrides: object) -> HostInsight:
        base: dict = {
            "hostname": f"api.{target_apex}",
            "role": HostRole.API,
            "priority": HostPriority.HIGH,
            "notes": (
                "Public REST API gateway running Spring Boot 2.6 behind Nginx; "
                "primary target for the programme."
            ),
            "detected_tech": ["Nginx", "Spring Boot 2.6"],
        }
        base.update(overrides)
        return HostInsight(**base)

    return _make


@pytest.fixture()
def endpoint(target_apex: str) -> Endpoint:
    return Endpoint(
        url=f"https://api.{target_apex}",
        status_code=200,
        technologies=["nginx", "React"],
        parameters=["q", "page"],
    )


@pytest.fixture()
def recon_result(programme, endpoint, target_apex: str) -> AttackGraph:
    return AttackGraph(
        programme=programme,
        subdomains=[f"api.{target_apex}", f"admin.{target_apex}"],
        endpoints=[endpoint],
        open_ports={f"api.{target_apex}": [80, 443]},
        technologies=["nginx", "React"],
        notes="Test recon result.",
    )


@pytest.fixture()
def make_s3_hostname(target_sld: str) -> Callable[..., str]:
    """Factory for in-scope-themed S3 hostnames.

    ``make_s3_hostname("assets")`` -> ``"example-assets.s3.us-east-1.amazonaws.com"``;
    ``make_s3_hostname()`` -> ``"example.s3.us-east-1.amazonaws.com"``.
    Override ``region`` for variants.
    """

    def _make(suffix: str = "", *, region: str = "us-east-1") -> str:
        bucket = f"{target_sld}-{suffix}" if suffix else target_sld
        return f"{bucket}.s3.{region}.amazonaws.com"

    return _make


@pytest.fixture()
def s3_hostname(make_s3_hostname: Callable[..., str]) -> str:
    """Single canonical S3 hostname for the simple cases - the suite's
    equivalent of ``target_url`` for AWS S3. Use ``make_s3_hostname``
    when a test needs more than one or a non-default region."""
    return make_s3_hostname("assets")


@pytest.fixture()
def make_azure_blob_hostname(target_sld: str) -> Callable[..., str]:
    """Factory for in-scope-themed Azure Blob hostnames.

    ``make_azure_blob_hostname("storage")`` ->
    ``"examplestorage.blob.core.windows.net"``. Azure storage account
    names are 3-24 lowercase alphanumeric (no hyphens), so the suffix
    concatenates without a separator.
    """

    def _make(suffix: str = "") -> str:
        account = f"{target_sld}{suffix}"
        return f"{account}.blob.core.windows.net"

    return _make


@pytest.fixture()
def azure_blob_hostname(make_azure_blob_hostname: Callable[..., str]) -> str:
    """Single canonical Azure Blob hostname for the simple cases."""
    return make_azure_blob_hostname("storage")


@pytest.fixture()
def azure_sas_endpoint(target_url: str) -> Endpoint:
    """``Endpoint`` whose URL carries embedded Azure SAS-token query
    parameters - the canonical positive case for
    ``check_azure_sas_tokens``. Built on ``target_url`` so the host
    is in-scope; the test exercises the query-string detection."""
    return Endpoint(
        url=(f"{target_url}/files/doc.pdf?sv=2021-01-01&se=2025-12-31&sr=b&sp=r&sig=abc123"),
        status_code=200,
    )
