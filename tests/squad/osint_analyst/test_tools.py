"""
tests/squad/osint_analyst/test_tools.py - exercise the @tool wrappers on the
OSINT Analyst.

The wrappers are thin: unmarshal JSON, call into tools/* helpers, serialise
the result. Coverage here is regression coverage of the wrapping itself; the
underlying helpers are exercised in their own dedicated test files.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tests.fixtures.programme import stage_model_json

pytestmark = pytest.mark.unit


class TestOsintAnalystTools:
    def test_list_subdomains_tool_wraps_hostnames_as_fqdn(self, target_apex) -> None:
        # Thin wrapper: list[str] from the impl becomes list[FQDN] for the
        # agent so the typed primitive's validator fires at the wrapper
        # boundary, not inside the consumer.
        from squad.osint_analyst import list_subdomains_tool

        with patch(
            "squad.osint_analyst.discovery.recon_subdomains",
            return_value=[f"api.{target_apex}", f"admin.{target_apex}"],
        ) as mimpl:
            result = list_subdomains_tool.func(
                attack_graph_path="attack_graph.json", host_filter="api"
            )

        assert result == [f"api.{target_apex}", f"admin.{target_apex}"]
        mimpl.assert_called_once_with("attack_graph.json", host_filter="api")

    def test_list_endpoints_tool_returns_endpoint_page(self, target_apex) -> None:
        # Thin wrapper over the recon_endpoints slicer: forwards the filter
        # args and hands back the typed EndpointPage the agent reads.
        from models import Endpoint, EndpointPage
        from squad.osint_analyst import list_endpoints_tool

        page = EndpointPage(
            endpoints=[Endpoint(url=f"https://api.{target_apex}", status_code=200)],
            total=1,
            offset=0,
            returned=1,
        )
        with patch(
            "squad.osint_analyst.discovery.recon_endpoints",
            return_value=page,
        ) as mimpl:
            result = list_endpoints_tool.func(
                attack_graph_path="attack_graph.json", status=200, tech="nginx"
            )

        assert result is page
        mimpl.assert_called_once_with(
            "attack_graph.json",
            status=200,
            tech="nginx",
            host_contains=None,
            offset=0,
            limit=50,
        )

    def test_list_open_ports_tool_wraps_dict_as_open_ports_map(self, target_apex) -> None:
        # Wrapper turns the impl's ``{host: [ports]}`` into the typed
        # ``OpenPortsMap`` the agent reads back.
        from models import OpenPortsMap
        from squad.osint_analyst import list_open_ports_tool

        host = f"api.{target_apex}"
        with patch(
            "squad.osint_analyst.discovery.recon_open_ports",
            return_value={host: [80, 443]},
        ) as mimpl:
            result = list_open_ports_tool.func(attack_graph_path="attack_graph.json", host=host)

        assert isinstance(result, OpenPortsMap)
        assert result.hosts == {host: [80, 443]}
        mimpl.assert_called_once_with("attack_graph.json", host=host)

    def test_run_initial_sweep_tool(self, programme_in_workspace, recon_result, tmp_path) -> None:
        from squad.osint_analyst import run_initial_sweep_tool

        with patch("squad.osint_analyst.discovery.run_recon", return_value=recon_result) as mrun:
            result = run_initial_sweep_tool.func()

        assert result == "attack_graph.json"
        assert (tmp_path / "attack_graph.json").exists()
        mrun.assert_called_once_with(programme_in_workspace)

    def test_annotate_host_tool_writes_insight_and_returns_validation(
        self, programme_in_workspace, recon_result, tmp_path, target_apex
    ) -> None:
        from squad.osint_analyst import annotate_host_tool

        stage_model_json(tmp_path, "attack_graph.json", recon_result)

        host = f"api.{target_apex}"
        result = annotate_host_tool.func(
            hostname=host,
            role="api",
            priority="high",
            notes=(
                "Public REST gateway running Nginx in front of a React SPA; "
                "primary attack surface for the programme."
            ),
            detected_tech=["Nginx", "React"],
        )

        from models import HostAnnotation

        assert isinstance(result, HostAnnotation)
        assert result.validation.ok is True
        assert (tmp_path / "assets" / host / "insight.json").exists()

    def test_annotate_host_tool_surfaces_validation_issues(
        self, programme_in_workspace, recon_result, tmp_path, target_apex
    ) -> None:
        from squad.osint_analyst import annotate_host_tool

        stage_model_json(tmp_path, "attack_graph.json", recon_result)

        result = annotate_host_tool.func(
            hostname=f"api.{target_apex}",
            role="api",
            priority="high",
            notes="too short",  # < 30 chars, also < 60 high-priority floor
            detected_tech=["Nginx"],
        )

        from models import HostAnnotation

        assert isinstance(result, HostAnnotation)
        assert result.validation.ok is False
        sections = {i.section for i in result.validation.issues}
        assert "notes" in sections

    def test_list_uncovered_hosts_tool_returns_missing(
        self, programme, recon_result, run_dir, target_apex
    ) -> None:
        from squad.osint_analyst import list_uncovered_hosts_tool

        stage_model_json(run_dir, "attack_graph.json", recon_result)
        result = list_uncovered_hosts_tool.func()

        assert isinstance(result, list)
        # recon_result's endpoint (https://api.<apex>, status 200) is interesting
        # and uncovered -> surfaces here, as a typed FQDN.
        assert f"api.{target_apex}" in result

    def test_finalise_recon_tool_writes_recon_json(
        self, programme_in_workspace, recon_result, run_dir, target_apex
    ) -> None:
        from squad.osint_analyst import annotate_host_tool, finalise_recon_tool

        stage_model_json(run_dir, "attack_graph.json", recon_result)

        annotate_host_tool.func(
            hostname=f"api.{target_apex}",
            role="api",
            priority="high",
            notes=(
                "Public REST gateway running Nginx in front of a React SPA; "
                "primary attack surface for the programme."
            ),
            detected_tech=["Nginx", "React"],
        )
        result = finalise_recon_tool.func()

        assert result == "recon.json"
        assert (run_dir / "recon.json").exists()

    def test_finalise_recon_tool_raises_without_insights(
        self, programme_in_workspace, recon_result, run_dir
    ) -> None:
        from squad.osint_analyst import finalise_recon_tool

        stage_model_json(run_dir, "attack_graph.json", recon_result)

        with pytest.raises(ValueError, match="no host insights"):
            finalise_recon_tool.func()

    def test_discover_webpages_tool(self, programme_in_workspace, endpoint, target_apex) -> None:
        """Happy path: in-scope hostname passes the wrapper's scope filter,
        the body fires, the endpoint is returned.

        Exercises the real ``filter_in_scope`` against the fixture
        programme (in-scope: the apex + its wildcard) - an ``api.``
        subdomain matches the wildcard, so the wrapper hands the body
        the cleaned hostname.
        """
        from squad.osint_analyst import discover_webpages_tool

        with patch(
            "squad.osint_analyst.discovery.probe_endpoints_impl",
            return_value=[endpoint],
        ):
            result = discover_webpages_tool.func([f"api.{target_apex}"])

        assert isinstance(result, list)
        assert result[0].url == endpoint.url

    def test_discover_webpages_tool_empty_list(self) -> None:
        """Empty input short-circuits in the body without touching the
        workspace - no ``current_programme()`` lookup, no run dir read."""
        from squad.osint_analyst import discover_webpages_tool

        assert discover_webpages_tool.func([]) == []

    def test_discover_webpages_tool_drops_out_of_scope(
        self, programme_in_workspace, bystander_url, invoke_tool
    ) -> None:
        """Out-of-scope hostnames are dropped at args_schema validation
        before the body fires.

        Asserts on the real scope-guard path: the fixture programme's
        structured scope (``example.com`` + ``*.example.com``) does not
        cover ``bystander.example.org``, so the ``TargetFQDNs``
        validator empties the list and ``probe_endpoints_impl`` is
        never called.
        """
        from urllib.parse import urlparse

        from squad.osint_analyst import discover_webpages_tool

        oos_host = urlparse(bystander_url).hostname
        mprobe = MagicMock()
        with patch("squad.osint_analyst.discovery.probe_endpoints_impl", mprobe):
            result = invoke_tool(discover_webpages_tool, hostnames=[oos_host])

        assert result == []
        mprobe.assert_not_called()

    def test_discover_takeover_candidates_tool(self, programme_in_workspace, target_apex) -> None:
        from squad.osint_analyst import discover_takeover_candidates_tool
        from tools.recon.dnsx import TakeoverCandidate

        host = f"legacy.{target_apex}"
        candidate = TakeoverCandidate(
            hostname=host,
            cname="bucket.s3.amazonaws.com",
            reason="cname_to_vulnerable_provider",
            service="AWS S3",
        )
        with patch(
            "squad.osint_analyst.discovery.detect_takeover_candidates",
            return_value=[candidate],
        ):
            result = discover_takeover_candidates_tool.func([host])

        assert isinstance(result, list)
        assert result == [candidate]

    def test_discover_takeover_candidates_tool_empty(self) -> None:
        from squad.osint_analyst import discover_takeover_candidates_tool

        assert discover_takeover_candidates_tool.func([]) == []

    def test_discover_takeover_candidates_tool_drops_out_of_scope(
        self, programme_in_workspace, bystander_url, invoke_tool
    ) -> None:
        """Same scope-guard contract as ``test_discover_webpages_tool_drops_out_of_scope``,
        on the DNS side: the ``TargetFQDNs`` validator drops the
        out-of-scope hostname at args_schema time, before any DNS
        traffic fires."""
        from urllib.parse import urlparse

        from squad.osint_analyst import discover_takeover_candidates_tool

        oos_host = urlparse(bystander_url).hostname
        mdetect = MagicMock()
        with patch("squad.osint_analyst.discovery.detect_takeover_candidates", mdetect):
            result = invoke_tool(discover_takeover_candidates_tool, hostnames=[oos_host])

        assert result == []
        mdetect.assert_not_called()

    def test_lookup_cwe_tool(self) -> None:
        from models import CWE
        from squad.osint_analyst import lookup_cwe_tool

        result = lookup_cwe_tool.func(79)
        assert isinstance(result, list)
        assert result
        assert isinstance(result[0], CWE)
        assert result[0].cwe_id == 79

    def test_lookup_owasp_tool(self) -> None:
        from squad.osint_analyst import lookup_owasp_tool
        from tools.owasp_data import OWASPEntry

        result = lookup_owasp_tool.func("sql injection")
        assert isinstance(result, list)
        assert all(isinstance(r, OWASPEntry) for r in result)
        assert any("SQL_Injection_Prevention" in r.url for r in result)

    def test_discover_subdomains_tool(self, target_apex) -> None:
        from squad.osint_analyst import discover_subdomains_tool

        names = [f"api.{target_apex}", f"admin.{target_apex}"]
        with patch(
            "squad.osint_analyst.discovery.cert_transparency",
            return_value=names,
        ) as m:
            result = discover_subdomains_tool.func(target_apex)

        # The wrapper coerces crt.sh's raw hostnames into typed FQDNs.
        assert result == names
        m.assert_called_once_with(target_apex)

    def test_discover_historical_urls_tool(self, target_apex) -> None:
        from squad.osint_analyst import discover_historical_urls_tool

        good = f"https://{target_apex}/old"
        # waybackurls occasionally emits a schemeless / malformed entry; the
        # wrapper drops it rather than failing the whole batch.
        with patch(
            "squad.osint_analyst.discovery.historical_urls",
            return_value=[good, "not a url", f"{target_apex}/no-scheme"],
        ) as m:
            result = discover_historical_urls_tool.func(target_apex)

        # The wrapper coerces waybackurls' raw strings into typed HttpUrls,
        # keeping only the well-formed ones.
        assert result == [good]
        m.assert_called_once_with(target_apex)

    def test_discover_llm_endpoints_tool(self, programme_in_workspace, endpoint) -> None:
        from models import LlmEndpoint
        from squad.osint_analyst import discover_llm_endpoints_tool

        # CrewAI's args_schema validation hands us list[dict] at runtime;
        # the both-shape adapter inside the wrapper accepts either Endpoint
        # instances or dicts, so this exercises the dict path.
        endpoints_payload = [endpoint.model_dump(mode="json")]
        with patch(
            "squad.osint_analyst.discovery.detect_llm_endpoints",
            return_value=[endpoint],
        ) as m:
            result = discover_llm_endpoints_tool.func(endpoints_payload)

        assert result == [LlmEndpoint.model_validate(endpoint.model_dump())]
        assert len(m.call_args[0][0]) == 1
