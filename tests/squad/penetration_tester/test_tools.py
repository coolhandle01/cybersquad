"""tests/squad/penetration_tester/test_tools.py - exercise the @tool
wrappers on the Penetration Tester.

The bespoke per-wrapper tests here cover the probe wrappers (Nuclei,
SQLMap, header / network probes), the recon-readers, and Save Findings -
each mocks the specific helper its wrapper forwards to. The typed cloud
wrappers (S3 / Azure / databases / panels / dashboards) are covered as a
group by the parametrize tables in ``test_cloud_wrappers.py``. The
underlying helpers are exercised in their own dedicated test files.

The endpoint-taking probe wrappers (Nuclei / SQLMap / SSRF) take a
``TargetEndpoints`` typed argument, so their args_schema carries the
scope guard - the ``AfterValidator`` that drops out-of-scope endpoints
before the wrapper body runs. Those wrappers are driven through
``invoke_tool`` (CrewAI's production path, which fires the validator),
never ``.func(...)`` (which bypasses it), and each is tested in *both*
directions: an in-scope endpoint reaches ``check_X``, an out-of-scope
endpoint does not. ``.func(...)`` alone would skip the validator, so a
mutant that let an out-of-scope host through - or one that dropped every
host, admitting nothing - would survive unnoticed.
"""

from __future__ import annotations

import json
from unittest.mock import patch
from urllib.parse import urlparse

import pytest

from tests.fixtures.programme import stage_model_json

pytestmark = pytest.mark.unit


class TestEndpointProbeScopeGuard:
    """The endpoint-taking probe wrappers (Nuclei / SQLMap / SSRF)
    scope-filter at the wrapper via their ``TargetEndpoints`` argument.
    Each is driven through ``invoke_tool`` so the args_schema's
    ``AfterValidator`` fires, and asserted in both directions: the
    in-scope endpoint reaches ``check_X`` (the accept path - a guard
    that admitted nothing would redden here), and the out-of-scope
    endpoint never does (the reject path)."""

    def test_nuclei_scan_forwards_in_scope_endpoint(
        self, programme_in_workspace, endpoint, raw_finding_low, invoke_tool
    ) -> None:
        from squad.penetration_tester import nuclei_scan_tool

        with patch(
            "squad.penetration_tester.tools.probes.external.run_nuclei",
            return_value=[raw_finding_low],
        ) as mrun:
            result = invoke_tool(
                nuclei_scan_tool,
                endpoints=[endpoint.model_dump(mode="json")],
                tech_tags=["wordpress"],
            )

        assert result == [raw_finding_low]
        # Pin what reached the scanner: the in-scope endpoint survived the
        # guard, and the tag list was forwarded verbatim.
        mrun.assert_called_once()
        passed_endpoints = mrun.call_args.args[0]
        assert [ep.url for ep in passed_endpoints] == [endpoint.url]
        assert mrun.call_args.kwargs["tech_tags"] == ["wordpress"]

    def test_nuclei_scan_drops_out_of_scope_endpoint(
        self, programme_in_workspace, bystander_url, raw_finding_low, invoke_tool
    ) -> None:
        from squad.penetration_tester import nuclei_scan_tool

        oos_host = urlparse(bystander_url).hostname
        with patch(
            "squad.penetration_tester.tools.probes.external.run_nuclei",
            return_value=[],
        ) as mrun:
            result = invoke_tool(
                nuclei_scan_tool,
                endpoints=[{"url": bystander_url, "status_code": 200}],
                tech_tags=["wordpress"],
            )

        assert result == []
        # The guard dropped the out-of-scope endpoint before the body ran;
        # the scanner was handed the empty survivor list, never the bystander.
        passed_endpoints = mrun.call_args.args[0]
        assert passed_endpoints == []
        assert oos_host not in [urlparse(str(ep.url)).hostname for ep in passed_endpoints]

    def test_sqlmap_forwards_in_scope_endpoint(
        self, programme_in_workspace, endpoint, raw_finding_low, invoke_tool
    ) -> None:
        from squad.penetration_tester import sqlmap_tool

        with patch(
            "squad.penetration_tester.tools.probes.injection.run_sqlmap",
            return_value=[raw_finding_low],
        ) as mrun:
            result = invoke_tool(sqlmap_tool, endpoints=[endpoint.model_dump(mode="json")])

        assert result == [raw_finding_low]
        mrun.assert_called_once()
        passed_endpoints = mrun.call_args.args[0]
        assert [ep.url for ep in passed_endpoints] == [endpoint.url]

    def test_sqlmap_drops_out_of_scope_endpoint(
        self, programme_in_workspace, bystander_url, invoke_tool
    ) -> None:
        from squad.penetration_tester import sqlmap_tool

        oos_host = urlparse(bystander_url).hostname
        with patch(
            "squad.penetration_tester.tools.probes.injection.run_sqlmap",
            return_value=[],
        ) as mrun:
            result = invoke_tool(
                sqlmap_tool, endpoints=[{"url": bystander_url, "status_code": 200}]
            )

        assert result == []
        passed_endpoints = mrun.call_args.args[0]
        assert passed_endpoints == []
        assert oos_host not in [urlparse(str(ep.url)).hostname for ep in passed_endpoints]

    def test_ssrf_probe_forwards_in_scope_endpoint(
        self, programme_in_workspace, endpoint, raw_finding_low, invoke_tool
    ) -> None:
        from squad.penetration_tester import ssrf_probe_tool

        with patch(
            "squad.penetration_tester.tools.probes.network.check_ssrf",
            return_value=[raw_finding_low],
        ) as mcheck:
            result = invoke_tool(
                ssrf_probe_tool,
                endpoints=[endpoint.model_dump(mode="json")],
                payloads=None,
            )

        assert result == [raw_finding_low]
        mcheck.assert_called_once()
        passed_endpoints = mcheck.call_args.args[0]
        assert [ep.url for ep in passed_endpoints] == [endpoint.url]

    def test_ssrf_probe_drops_out_of_scope_endpoint(
        self, programme_in_workspace, bystander_url, invoke_tool
    ) -> None:
        from squad.penetration_tester import ssrf_probe_tool

        oos_host = urlparse(bystander_url).hostname
        with patch(
            "squad.penetration_tester.tools.probes.network.check_ssrf",
            return_value=[],
        ) as mcheck:
            result = invoke_tool(
                ssrf_probe_tool,
                endpoints=[{"url": bystander_url, "status_code": 200}],
                payloads=None,
            )

        assert result == []
        passed_endpoints = mcheck.call_args.args[0]
        assert passed_endpoints == []
        assert oos_host not in [urlparse(str(ep.url)).hostname for ep in passed_endpoints]


class TestReconPathProbeForwarding:
    """The header / cookie / CSRF probe wrappers take a ``recon_path``
    string (scope was enforced upstream when ``recon.json`` was written),
    load the AttackGraph, and forward its endpoints to ``check_X``. These
    have no wrapper-level scope guard, so the observation that matters is
    that the recon surface actually reaches the checker - asserted against
    ``recon_result.endpoints`` rather than the stub's return value, so a
    mutant that forwarded a different (or empty) endpoint set would redden."""

    def test_cookie_check_tool(self, recon_result, raw_finding_low, run_dir, invoke_tool) -> None:
        from squad.penetration_tester import cookie_check_tool

        stage_model_json(run_dir, "recon.json", recon_result)
        with patch(
            "squad.penetration_tester.tools.probes.headers.check_cookies",
            return_value=[raw_finding_low],
        ) as mcheck:
            result = invoke_tool(cookie_check_tool, recon_path="recon.json")

        assert result == [raw_finding_low]
        mcheck.assert_called_once_with(recon_result.endpoints)

    def test_cors_check_tool(self, recon_result, raw_finding_low, run_dir, invoke_tool) -> None:
        from squad.penetration_tester import cors_check_tool

        stage_model_json(run_dir, "recon.json", recon_result)
        with patch(
            "squad.penetration_tester.tools.probes.headers.check_cors_misconfiguration",
            return_value=[raw_finding_low],
        ) as mcheck:
            result = invoke_tool(cors_check_tool, recon_path="recon.json")

        assert result == [raw_finding_low]
        mcheck.assert_called_once_with(recon_result.endpoints)

    def test_csrf_check_tool(self, recon_result, raw_finding_low, run_dir, invoke_tool) -> None:
        from squad.penetration_tester import csrf_check_tool

        stage_model_json(run_dir, "recon.json", recon_result)
        with patch(
            "squad.penetration_tester.tools.probes.headers.check_csrf",
            return_value=[raw_finding_low],
        ) as mcheck:
            result = invoke_tool(csrf_check_tool, recon_path="recon.json")

        assert result == [raw_finding_low]
        mcheck.assert_called_once_with(recon_result.endpoints)

    def test_header_injection_tool(
        self, recon_result, raw_finding_low, run_dir, invoke_tool
    ) -> None:
        from squad.penetration_tester import header_injection_tool

        stage_model_json(run_dir, "recon.json", recon_result)
        with patch(
            "squad.penetration_tester.tools.probes.headers.check_header_injection",
            return_value=[raw_finding_low],
        ) as mcheck:
            result = invoke_tool(header_injection_tool, recon_path="recon.json")

        assert result == [raw_finding_low]
        mcheck.assert_called_once_with(recon_result.endpoints)

    def test_host_header_tool(self, recon_result, raw_finding_low, run_dir, invoke_tool) -> None:
        from squad.penetration_tester import host_header_tool

        stage_model_json(run_dir, "recon.json", recon_result)
        with patch(
            "squad.penetration_tester.tools.probes.headers.check_host_headers",
            return_value=[raw_finding_low],
        ) as mcheck:
            result = invoke_tool(host_header_tool, recon_path="recon.json")

        assert result == [raw_finding_low]
        mcheck.assert_called_once_with(recon_result.endpoints)


class TestPenetrationTesterTools:
    def test_save_findings_tool(self, raw_finding_low, run_dir) -> None:
        from models import RawFinding
        from squad.penetration_tester import save_findings_tool

        result = save_findings_tool.func([raw_finding_low.model_dump(mode="json")])

        assert result == "findings.json"
        persisted = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
        assert [RawFinding.model_validate(f) for f in persisted] == [raw_finding_low]

    def test_recon_subdomains_tool(self, recon_result, run_dir) -> None:
        from squad.penetration_tester import recon_subdomains_tool

        stage_model_json(run_dir, "recon.json", recon_result)
        result = recon_subdomains_tool.func("recon.json")
        assert result == recon_result.subdomains

    def test_recon_endpoints_tool(self, recon_result, run_dir) -> None:
        from squad.penetration_tester import recon_endpoints_tool

        stage_model_json(run_dir, "recon.json", recon_result)
        result = recon_endpoints_tool.func("recon.json", status=200)
        from models import EndpointPage

        assert isinstance(result, EndpointPage)
        assert result.total == 1
        assert result.endpoints[0].url == recon_result.endpoints[0].url

    def test_recon_open_ports_tool(self, recon_result, run_dir) -> None:
        from squad.penetration_tester import recon_open_ports_tool

        stage_model_json(run_dir, "recon.json", recon_result)
        from models import OpenPortsMap

        result = recon_open_ports_tool.func("recon.json")
        assert isinstance(result, OpenPortsMap)
        assert result.hosts == recon_result.open_ports
