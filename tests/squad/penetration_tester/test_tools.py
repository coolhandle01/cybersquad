"""tests/squad/penetration_tester/test_tools.py - exercise the @tool
wrappers on the Penetration Tester.

The bespoke per-wrapper tests here cover the probe wrappers (Nuclei,
SQLMap, header / network probes), the recon-readers, and Save Findings -
each mocks the specific helper its wrapper forwards to. The typed cloud
wrappers (S3 / Azure / databases / panels / dashboards) are covered as a
group by the parametrize tables in ``test_cloud_wrappers.py``. The
underlying helpers are exercised in their own dedicated test files.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from tests.fixtures.programme import stage_model_json

pytestmark = pytest.mark.unit


class TestPenetrationTesterTools:
    def test_nuclei_scan_tool(self, programme_in_workspace, endpoint, raw_finding_low) -> None:
        from squad.penetration_tester import nuclei_scan_tool

        with patch(
            "squad.penetration_tester.tools.probes.external.run_nuclei",
            return_value=[raw_finding_low],
        ):
            result = nuclei_scan_tool.func([endpoint.model_dump(mode="json")], ["wordpress"])

        assert result == [raw_finding_low]

    def test_sqlmap_tool(self, programme_in_workspace, endpoint, raw_finding_low) -> None:
        from squad.penetration_tester import sqlmap_tool

        with patch(
            "squad.penetration_tester.tools.probes.injection.run_sqlmap",
            return_value=[raw_finding_low],
        ):
            result = sqlmap_tool.func([endpoint.model_dump(mode="json")])

        assert result == [raw_finding_low]

    def test_cookie_check_tool(self, recon_result, raw_finding_low, run_dir) -> None:
        from squad.penetration_tester import cookie_check_tool

        stage_model_json(run_dir, "recon.json", recon_result)
        with patch(
            "squad.penetration_tester.tools.probes.headers.check_cookies",
            return_value=[raw_finding_low],
        ):
            result = cookie_check_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_cors_check_tool(self, recon_result, raw_finding_low, run_dir) -> None:
        from squad.penetration_tester import cors_check_tool

        stage_model_json(run_dir, "recon.json", recon_result)
        with patch(
            "squad.penetration_tester.tools.probes.headers.check_cors_misconfiguration",
            return_value=[raw_finding_low],
        ):
            result = cors_check_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_csrf_check_tool(self, recon_result, raw_finding_low, run_dir) -> None:
        from squad.penetration_tester import csrf_check_tool

        stage_model_json(run_dir, "recon.json", recon_result)
        with patch(
            "squad.penetration_tester.tools.probes.headers.check_csrf",
            return_value=[raw_finding_low],
        ):
            result = csrf_check_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_ssrf_probe_tool(self, programme_in_workspace, endpoint, raw_finding_low) -> None:
        from squad.penetration_tester import ssrf_probe_tool

        with patch(
            "squad.penetration_tester.tools.probes.network.check_ssrf",
            return_value=[raw_finding_low],
        ):
            result = ssrf_probe_tool.func([endpoint.model_dump(mode="json")], None)

        assert result == [raw_finding_low]

    def test_header_injection_tool(self, recon_result, raw_finding_low, run_dir) -> None:
        from squad.penetration_tester import header_injection_tool

        stage_model_json(run_dir, "recon.json", recon_result)
        with patch(
            "squad.penetration_tester.tools.probes.headers.check_header_injection",
            return_value=[raw_finding_low],
        ):
            result = header_injection_tool.func("recon.json")

        assert result == [raw_finding_low]

    def test_host_header_tool(self, recon_result, raw_finding_low, run_dir) -> None:
        from squad.penetration_tester import host_header_tool

        stage_model_json(run_dir, "recon.json", recon_result)
        with patch(
            "squad.penetration_tester.tools.probes.headers.check_host_headers",
            return_value=[raw_finding_low],
        ):
            result = host_header_tool.func("recon.json")

        assert result == [raw_finding_low]

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
