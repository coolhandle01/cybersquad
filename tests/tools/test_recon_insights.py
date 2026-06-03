"""tests/tools/test_recon_insights.py - unit tests for tools/recon_insights.py."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from models import (
    AttackGraph,
    Endpoint,
    HostInsight,
    HostPriority,
    HostRole,
    TLSCertificate,
    VulnProperty,
)
from tests.fixtures.programme import stage_model_json
from tools.recon_insights import (
    ReconFinalisationError,
    annotate_host_vulns,
    finalise_recon,
    load_insights,
    load_tls_certificates,
    save_insight,
    uncovered_interesting_hosts,
    validate_insight,
)

pytestmark = pytest.mark.unit


# Fixtures
#
# The `programme` (with its `*.example.com` wildcard) and the `bystander_url`
# fixture (out-of-scope by construction) come from tests/conftest.py.


@pytest.fixture
def sweep(programme, target_apex) -> AttackGraph:
    return AttackGraph(
        programme=programme,
        subdomains=[f"api.{target_apex}", f"admin.{target_apex}", f"cdn.{target_apex}"],
        endpoints=[
            Endpoint(
                url=f"https://api.{target_apex}",
                status_code=200,
                technologies=["Nginx", "Spring Boot 2.6"],
            ),
            Endpoint(
                url=f"https://admin.{target_apex}",
                status_code=401,
                technologies=["WordPress 5.8"],
            ),
            Endpoint(
                url=f"https://cdn.{target_apex}",
                status_code=200,
                technologies=["CloudFront"],
            ),
            Endpoint(
                url=f"https://dead.{target_apex}",
                status_code=500,
                technologies=[],
            ),
        ],
    )


# Validation


class TestValidateInsight:
    def test_clean_insight_passes(self, make_host_insight, sweep, programme):
        report = validate_insight(make_host_insight(), sweep, programme)
        assert report.ok is True
        assert all(i.severity != "error" for i in report.issues)

    def test_rejects_empty_hostname(self, make_host_insight):
        # FQDN is a typed-string with an upstream validator now, so the
        # empty-hostname check fires at HostInsight construction time rather
        # than inside validate_insight. The test asserts the contract has
        # moved one layer up rather than re-asserting the (now-redundant)
        # validate_insight branch.
        with pytest.raises(ValidationError):
            make_host_insight(hostname="")

    def test_rejects_out_of_scope_hostname(
        self, make_host_insight, sweep, programme, bystander_url
    ):
        from urllib.parse import urlparse

        oos_host = urlparse(bystander_url).hostname
        report = validate_insight(make_host_insight(hostname=oos_host), sweep, programme)
        assert report.ok is False
        assert any(
            i.section == "hostname" and "not in programme scope" in i.message for i in report.issues
        )

    def test_rejects_thin_notes(self, make_host_insight, sweep, programme):
        report = validate_insight(make_host_insight(notes="too short"), sweep, programme)
        assert report.ok is False
        assert any(i.section == "notes" for i in report.issues)

    def test_rejects_thin_notes_on_high_priority(self, make_host_insight, sweep, programme):
        # 35 chars is >= 30 (so not the basic floor) but < 60 (the high-priority floor)
        thirty_five = "Public API gateway hosting v2 routes."
        report = validate_insight(make_host_insight(notes=thirty_five), sweep, programme)
        assert report.ok is False
        assert any(
            i.section == "notes" and "high-priority hosts" in i.message for i in report.issues
        )

    def test_rejects_thin_notes_on_skip(self, make_host_insight, sweep, programme):
        report = validate_insight(
            make_host_insight(priority=HostPriority.SKIP, notes="skip"),
            sweep,
            programme,
        )
        assert report.ok is False
        assert any(i.section == "notes" for i in report.issues)

    def test_warns_when_agent_drops_sweep_tech(self, make_host_insight, sweep, programme):
        # sweep saw ['Nginx', 'Spring Boot 2.6']; agent only carries 'Nginx'
        report = validate_insight(
            make_host_insight(detected_tech=["Nginx"]),
            sweep,
            programme,
        )
        assert report.ok is True
        assert any(i.section == "detected_tech" and i.severity == "warning" for i in report.issues)

    def test_accepts_when_agent_adds_version_to_sweep_tech(
        self, make_host_insight, sweep, programme
    ):
        # sweep saw 'Spring Boot 2.6'; agent carries 'Spring Boot 2.6.3' (more specific)
        report = validate_insight(
            make_host_insight(detected_tech=["Nginx", "Spring Boot 2.6.3"]),
            sweep,
            programme,
        )
        # The version-stripping check accepts more-specific versions, but the
        # exact comparison may still warn. Either way, no errors.
        assert report.ok is True

    def test_rejects_trivial_tech_entry(self, make_host_insight, sweep, programme):
        report = validate_insight(
            make_host_insight(detected_tech=["X"]),
            sweep,
            programme,
        )
        assert report.ok is False
        assert any(i.section == "detected_tech" for i in report.issues)


# Coverage helper


class TestUncoveredInterestingHosts:
    def test_returns_hosts_without_insights(self, sweep, target_apex):
        # No insights yet, all interesting hosts uncovered
        uncovered = uncovered_interesting_hosts(sweep, [])
        # api / admin / cdn are 200/401/200 (interesting); dead is 500 (skip)
        assert set(uncovered) == {
            f"api.{target_apex}",
            f"admin.{target_apex}",
            f"cdn.{target_apex}",
        }

    def test_drops_hosts_with_insights(self, make_host_insight, sweep, target_apex):
        uncovered = uncovered_interesting_hosts(
            sweep,
            [make_host_insight(hostname=f"api.{target_apex}")],
        )
        assert f"api.{target_apex}" not in uncovered
        assert f"admin.{target_apex}" in uncovered

    def test_excludes_uninteresting_status(self, sweep, target_apex):
        uncovered = uncovered_interesting_hosts(sweep, [])
        assert f"dead.{target_apex}" not in uncovered


# Finalisation


def _write_sweep(run_dir, sweep: AttackGraph) -> None:
    stage_model_json(run_dir, "attack_graph.json", sweep)


class TestFinaliseRecon:
    def test_writes_recon_json_for_clean_insights(
        self, make_host_insight, sweep, programme, run_dir, target_apex
    ):
        _write_sweep(run_dir, sweep)
        save_insight(make_host_insight())
        path = finalise_recon(programme)
        assert path == run_dir / "recon.json"
        data = json.loads(path.read_text())
        assert len(data["host_insights"]) == 1
        assert data["host_insights"][0]["hostname"] == f"api.{target_apex}"

    def test_refuses_without_insights(self, sweep, programme, run_dir):
        _write_sweep(run_dir, sweep)
        with pytest.raises(ReconFinalisationError, match="no host insights"):
            finalise_recon(programme)

    def test_refuses_when_no_high_priority(self, make_host_insight, sweep, programme, run_dir):
        _write_sweep(run_dir, sweep)
        save_insight(
            make_host_insight(
                priority=HostPriority.MEDIUM,
                notes="Standard public API with no version disclosed yet.",
            )
        )
        with pytest.raises(ReconFinalisationError, match="HIGH priority"):
            finalise_recon(programme)

    def test_refuses_on_validation_errors(self, make_host_insight, sweep, programme, run_dir):
        _write_sweep(run_dir, sweep)
        save_insight(make_host_insight(notes="too short"))
        with pytest.raises(ReconFinalisationError, match="unresolved errors"):
            finalise_recon(programme)

    def test_refuses_without_sweep(self, make_host_insight, programme, run_dir):
        save_insight(make_host_insight())
        with pytest.raises(FileNotFoundError, match=r"attack_graph\.json"):
            finalise_recon(programme)

    def test_carries_sweep_fields_through(self, make_host_insight, sweep, programme, run_dir):
        _write_sweep(run_dir, sweep)
        save_insight(make_host_insight())
        path = finalise_recon(programme)
        data = json.loads(path.read_text())
        assert data["subdomains"] == sweep.subdomains
        assert len(data["endpoints"]) == len(sweep.endpoints)


class TestMaterialiseUrls:
    def test_finalise_writes_urls_per_host(
        self, make_host_insight, sweep, programme, run_dir, target_apex
    ):
        from tools.recon_host_store import load_host_urls

        _write_sweep(run_dir, sweep)
        save_insight(make_host_insight())  # api.<apex>, HIGH
        finalise_recon(programme)

        urls = load_host_urls(f"api.{target_apex}")
        assert len(urls) == 1
        assert urls[0].scheme == "https"
        assert urls[0].host == f"api.{target_apex}"

    def test_finalise_skips_unparseable_url(
        self, make_host_insight, sweep, programme, run_dir, target_apex
    ):
        from models import Endpoint
        from tools.recon_host_store import load_host_urls

        # A URL between 2048 (the Url.raw cap) and 2083 (HttpUrl's own cap)
        # passes Endpoint but fails the Url shape; it must be skipped, not
        # abort finalisation (the good api endpoint on the same host persists).
        base = f"https://api.{target_apex}/"
        oversize = Endpoint(url=base + "a" * (2070 - len(base)))
        bad_sweep = sweep.model_copy(update={"endpoints": [*sweep.endpoints, oversize]})
        _write_sweep(run_dir, bad_sweep)
        save_insight(make_host_insight())
        finalise_recon(programme)

        urls = load_host_urls(f"api.{target_apex}")
        assert urls  # the good api URL persisted
        assert all(len(u.raw) <= 2048 for u in urls)  # the oversize one was skipped


class TestFinaliseMaterialisesHostDirs:
    def test_writes_every_facet(self, make_host_insight, sweep, programme, run_dir, target_apex):
        from models import RawFinding
        from tools.recon_insights import (
            host_score_path,
            load_host_findings,
            load_host_ports,
            notes_path,
        )

        enriched = sweep.model_copy(
            update={
                "open_ports": {f"api.{target_apex}": [443], f"empty.{target_apex}": []},
                "passive_findings": [
                    RawFinding(
                        title="weak TLS",
                        vuln_class="tls",
                        target=f"https://api.{target_apex}/x",
                        evidence="e",
                        tool="testssl",
                    ),
                    # empty target -> _finding_host yields "" -> skipped
                    RawFinding(
                        title="orphan", vuln_class="dns", target="", evidence="e", tool="dig"
                    ),
                ],
                "tls_certificates": [TLSCertificate(host=f"api.{target_apex}")],
            }
        )
        _write_sweep(run_dir, enriched)
        save_insight(make_host_insight())  # api.<apex>, HIGH
        finalise_recon(programme)

        # curation facets (from the insight)
        assert host_score_path(f"api.{target_apex}").is_file()
        assert "primary target" in notes_path(f"api.{target_apex}").read_text(encoding="utf-8")
        # fact facets (from the sweep)
        assert load_host_ports(f"api.{target_apex}") == [443]
        assert load_host_ports(f"empty.{target_apex}") == []  # empty list -> not written
        assert [f.title for f in load_host_findings(f"api.{target_apex}")] == ["weak TLS"]
        assert len(load_tls_certificates()) == 1

    def test_carries_enrichment_into_recon_json(
        self, make_host_insight, sweep, programme, run_dir, target_apex
    ):
        from models import DNSRecordProperty, IPAddress, IpEnrichment, RRHeader

        enriched = sweep.model_copy(
            update={
                "ip_enrichment": IpEnrichment(
                    ip_addresses=[IPAddress(address="8.8.8.8", type="IPv4")]
                ),
                "dns_records": [
                    DNSRecordProperty(
                        property_name=f"api.{target_apex}",
                        header=RRHeader(rr_type=1),
                        data="8.8.8.8",
                    )
                ],
                "tls_certificates": [TLSCertificate(host=f"api.{target_apex}")],
            }
        )
        _write_sweep(run_dir, enriched)
        save_insight(make_host_insight())
        out = finalise_recon(programme)
        final = AttackGraph.model_validate_json(out.read_text(encoding="utf-8"))
        # finalise rebuilds the graph by field; every sweep-gathered field must
        # survive the round-trip (the IP subgraph, DNS records, certs).
        assert len(final.ip_enrichment.ip_addresses) == 1
        assert len(final.dns_records) == 1
        assert len(final.tls_certificates) == 1


class TestAnnotateHostVulns:
    """The VR's hook onto the OAM graph: VulnProperty merged onto a host."""

    def _seed(self, target_apex: str) -> str:
        hostname = f"blog.{target_apex}"
        save_insight(
            HostInsight(
                hostname=hostname,
                role=HostRole.APP,
                priority=HostPriority.HIGH,
                notes="WordPress 5.8.1 blog host - dated core, worth a CVE pass here.",
                detected_tech=["WordPress 5.8.1"],
            )
        )
        return hostname

    def test_merges_and_persists(self, run_dir, target_apex):
        hostname = self._seed(target_apex)
        updated = annotate_host_vulns(
            hostname, [VulnProperty(id="CVE-2021-44223", source="nvd", enumeration="CVE")]
        )
        assert updated.vulns[0].id == "CVE-2021-44223"
        reloaded = next(i for i in load_insights() if i.hostname == hostname)
        assert reloaded.vulns[0].id == "CVE-2021-44223"

    def test_dedups_by_id(self, run_dir, target_apex):
        hostname = self._seed(target_apex)
        annotate_host_vulns(hostname, [VulnProperty(id="CVE-2021-44223")])
        updated = annotate_host_vulns(
            hostname,
            [VulnProperty(id="CVE-2021-44223"), VulnProperty(id="CVE-2022-21661")],
        )
        assert [v.id for v in updated.vulns] == ["CVE-2021-44223", "CVE-2022-21661"]

    def test_raises_when_host_has_no_insight(self, run_dir, target_apex):
        with pytest.raises(ValueError, match="no host insight"):
            annotate_host_vulns(f"ghost.{target_apex}", [VulnProperty(id="CVE-2021-44223")])
