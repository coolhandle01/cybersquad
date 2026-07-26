"""tests/tools/recon/nmap/test_scanner.py - unit tests for tools/recon/nmap/scanner.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models.scanner import (
    NmapBanner,
    NmapHostResult,
    NmapMode,
    NmapScanResult,
    NmapScripts,
)
from tools.recon.nmap import nmap_scan, port_scan
from tools.recon.nmap.scanner import _evidence_filename

pytestmark = pytest.mark.unit


class TestEvidenceFilename:
    def test_deterministic_for_same_hosts(self):
        a = _evidence_filename(["x.example", "y.example"], NmapMode.QUICK_PORTS)
        b = _evidence_filename(["x.example", "y.example"], NmapMode.QUICK_PORTS)
        assert a == b

    def test_order_independent(self):
        # Sort the input so {x, y} and {y, x} produce the same filename.
        a = _evidence_filename(["x.example", "y.example"], NmapMode.QUICK_PORTS)
        b = _evidence_filename(["y.example", "x.example"], NmapMode.QUICK_PORTS)
        assert a == b

    def test_mode_in_name(self):
        name = _evidence_filename(["x.example"], NmapMode.FULL_INVENTORY)
        assert "full-inventory" in name

    def test_filename_shape(self):
        name = _evidence_filename(["x.example"], NmapMode.QUICK_PORTS)
        assert name.startswith("nmap-")
        assert name.endswith(".xml")


class TestNmapScan:
    def _mock_subprocess_result(self, xml: str):
        result = MagicMock()
        result.stdout = xml
        result.returncode = 0
        result.stderr = ""
        return result

    def test_returns_typed_result_with_parsed_hosts(self, nmap_xml_two_hosts):
        mock_result = self._mock_subprocess_result(nmap_xml_two_hosts)
        with (
            patch("tools.recon.nmap.scanner._require_binary", return_value="/usr/bin/nmap"),
            patch("tools.recon.nmap.scanner._run", return_value=mock_result),
        ):
            result = nmap_scan(
                ["93.184.216.34", "93.184.216.35"],
                mode=NmapMode.SERVICE_VERSION,
                banner=NmapBanner.LIGHT,
                persist_evidence=False,
            )

        assert isinstance(result, NmapScanResult)
        assert result.mode == NmapMode.SERVICE_VERSION
        assert len(result.hosts) == 2
        assert all(isinstance(h, NmapHostResult) for h in result.hosts)

    def test_empty_host_list_short_circuits(self):
        # No subprocess invocation for empty input.
        with patch("tools.recon.nmap.scanner._require_binary") as mock_bin:
            result = nmap_scan([], mode=NmapMode.QUICK_PORTS)
        mock_bin.assert_not_called()
        assert result.hosts == []
        assert result.mode == NmapMode.QUICK_PORTS

    def test_subprocess_failure_returns_empty_result(self):
        # Network down / nmap missing -> degrade gracefully.
        with (
            patch("tools.recon.nmap.scanner._require_binary", return_value="/usr/bin/nmap"),
            patch("tools.recon.nmap.scanner._run", side_effect=OSError("nmap died")),
        ):
            result = nmap_scan(["x.example"], mode=NmapMode.QUICK_PORTS)
        assert result.hosts == []
        assert result.evidence_path is None

    def test_persist_evidence_writes_xml_to_run_dir(self, nmap_xml_two_hosts, run_dir):
        # ``run_dir`` fixture points runtime.run_dir() at tmp_path.
        mock_result = self._mock_subprocess_result(nmap_xml_two_hosts)
        with (
            patch("tools.recon.nmap.scanner._require_binary", return_value="/usr/bin/nmap"),
            patch("tools.recon.nmap.scanner._run", return_value=mock_result),
        ):
            result = nmap_scan(
                ["93.184.216.34"],
                mode=NmapMode.QUICK_PORTS,
                persist_evidence=True,
            )

        assert result.evidence_path is not None
        on_disk = run_dir / result.evidence_path
        assert on_disk.exists()
        assert on_disk.read_text(encoding="utf-8") == nmap_xml_two_hosts

    def test_persist_evidence_false_skips_write(self, nmap_xml_two_hosts, run_dir):
        mock_result = self._mock_subprocess_result(nmap_xml_two_hosts)
        with (
            patch("tools.recon.nmap.scanner._require_binary", return_value="/usr/bin/nmap"),
            patch("tools.recon.nmap.scanner._run", return_value=mock_result),
        ):
            result = nmap_scan(
                ["93.184.216.34"],
                mode=NmapMode.QUICK_PORTS,
                persist_evidence=False,
            )
        assert result.evidence_path is None
        # No XML files written to the rundir.
        assert not any(run_dir.glob("nmap-*.xml"))

    def test_persist_skipped_without_run_binding(self, nmap_xml_two_hosts):
        # No ``run_dir`` fixture -> runtime.run_dir() raises -> evidence
        # write is skipped gracefully, result still typed.
        mock_result = self._mock_subprocess_result(nmap_xml_two_hosts)
        with (
            patch("tools.recon.nmap.scanner._require_binary", return_value="/usr/bin/nmap"),
            patch("tools.recon.nmap.scanner._run", return_value=mock_result),
        ):
            result = nmap_scan(["x.example"], persist_evidence=True)
        assert result.evidence_path is None
        assert len(result.hosts) == 2  # parsing still happened

    def test_ports_threaded_into_command(self, nmap_xml_no_hosts):
        # nmap_scan(ports=...) reaches the assembled argv as -p <csv>,
        # the path Deep Scan Host rides for a focused re-scan.
        mock_result = self._mock_subprocess_result(nmap_xml_no_hosts)
        with (
            patch("tools.recon.nmap.scanner._require_binary", return_value="/usr/bin/nmap"),
            patch("tools.recon.nmap.scanner._run", return_value=mock_result) as mock_run,
        ):
            nmap_scan(
                ["x.example"],
                mode=NmapMode.SERVICE_VERSION,
                scripts=NmapScripts.DEFAULT,
                ports=[22, 443],
                persist_evidence=False,
            )
        cmd = mock_run.call_args.args[0]
        assert "-p" in cmd
        assert cmd[cmd.index("-p") + 1] == "22,443"
        assert "-F" not in cmd
        assert "--script=default" in cmd

    def test_command_uses_oX_dash_for_xml_stdout(self, nmap_xml_no_hosts):
        # Sanity: the assembled command pipes XML to stdout via -oX -,
        # not the grep format the old port_scan used.
        mock_result = self._mock_subprocess_result(nmap_xml_no_hosts)
        with (
            patch("tools.recon.nmap.scanner._require_binary", return_value="/usr/bin/nmap"),
            patch("tools.recon.nmap.scanner._run", return_value=mock_result) as mock_run,
        ):
            nmap_scan(["x.example"], persist_evidence=False)
        cmd = mock_run.call_args.args[0]
        # -oX argument appears with its '-' partner immediately after.
        assert "-oX" in cmd
        idx = cmd.index("-oX")
        assert cmd[idx + 1] == "-"


class TestPortScan:
    """``port_scan`` is the slim entry point the recon orchestrator calls:
    it runs ``nmap_scan`` under the hood and flattens the XML result to the
    ``{host: [open_ports]}`` shape callers expect."""

    def test_parses_open_ports(self):
        # nmap_scan emits -oX XML; port_scan parses the same XML and
        # flattens it to the {host: [open_ports]} shape.
        mock_result = MagicMock()
        mock_result.stdout = (
            '<?xml version="1.0"?>\n'
            "<nmaprun>"
            '<host><address addr="example.com" addrtype="ipv4"/>'
            "<ports>"
            '<port protocol="tcp" portid="80"><state state="open"/></port>'
            '<port protocol="tcp" portid="443"><state state="open"/></port>'
            "</ports>"
            "</host>"
            "</nmaprun>"
        )
        mock_result.returncode = 0
        mock_result.stderr = ""

        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = port_scan(["example.com"])

        assert 80 in result["example.com"]
        assert 443 in result["example.com"]

    def test_empty_host_list(self):
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            result = port_scan([])
        assert result == {}

    def test_raises_if_binary_missing(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(EnvironmentError, match="nmap"):
                port_scan(["example.com"])
