"""tests/tools/recon/nmap/test_flags.py - unit tests for tools/recon/nmap/flags.py."""

from __future__ import annotations

import pytest

from config import ScanMode as ConfigScanMode
from models.scanner import (
    NmapBanner,
    NmapMode,
    NmapScripts,
)
from tools.recon.nmap.flags import _assemble_flags

pytestmark = pytest.mark.unit


class TestAssembleFlags:
    def test_quick_ports_normal(self):
        flags = _assemble_flags(
            NmapMode.QUICK_PORTS,
            NmapBanner.NONE,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
        )
        assert "-sS" in flags and "-F" in flags and "-T3" in flags
        assert "-sV" not in flags  # banner-grab only with SERVICE_VERSION+

    def test_service_version_adds_sv(self):
        flags = _assemble_flags(
            NmapMode.SERVICE_VERSION,
            NmapBanner.LIGHT,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
        )
        assert "-sV" in flags
        assert "--version-intensity" in flags
        # Intensity argument follows --version-intensity.
        i = flags.index("--version-intensity")
        assert flags[i + 1] == "2"

    def test_banner_full_yields_intensity_9(self):
        flags = _assemble_flags(
            NmapMode.SERVICE_VERSION,
            NmapBanner.FULL,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
        )
        i = flags.index("--version-intensity")
        assert flags[i + 1] == "9"

    def test_banner_none_omits_intensity_arg(self):
        # NmapBanner.NONE with a -sV mode -> still no --version-intensity
        flags = _assemble_flags(
            NmapMode.SERVICE_VERSION,
            NmapBanner.NONE,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
        )
        assert "--version-intensity" not in flags

    def test_banner_ignored_on_quick_ports(self):
        # Even with NmapBanner.FULL, QUICK_PORTS does not run -sV so
        # no intensity argument is added.
        flags = _assemble_flags(
            NmapMode.QUICK_PORTS,
            NmapBanner.FULL,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
        )
        assert "--version-intensity" not in flags

    @pytest.mark.parametrize(
        ("scripts", "expected_expr"),
        [
            (NmapScripts.HTTP_HEADERS, "banner,http-server-header,http-title"),
            (NmapScripts.SAFE, "safe"),
            (NmapScripts.VULN, "vuln"),
            # DEFAULT is nmap's -sC bundle, expressed as --script=default.
            (NmapScripts.DEFAULT, "default"),
        ],
    )
    def test_scripts_argument(self, scripts, expected_expr):
        flags = _assemble_flags(
            NmapMode.FULL_INVENTORY,
            NmapBanner.LIGHT,
            scripts,
            ConfigScanMode.NORMAL,
        )
        assert f"--script={expected_expr}" in flags

    def test_scripts_none_omits_script_arg(self):
        flags = _assemble_flags(
            NmapMode.FULL_INVENTORY,
            NmapBanner.LIGHT,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
        )
        assert not any(f.startswith("--script=") for f in flags)

    @pytest.mark.parametrize(
        ("scan_mode", "expected_timing"),
        [
            (ConfigScanMode.STEALTH, "-T2"),
            (ConfigScanMode.NORMAL, "-T3"),
            (ConfigScanMode.RAID, "-T4"),
        ],
    )
    def test_scan_mode_timing(self, scan_mode, expected_timing):
        flags = _assemble_flags(
            NmapMode.QUICK_PORTS,
            NmapBanner.NONE,
            NmapScripts.NONE,
            scan_mode,
        )
        assert expected_timing in flags

    def test_stealth_adds_retry_and_host_timeout_caps(self):
        flags = _assemble_flags(
            NmapMode.QUICK_PORTS,
            NmapBanner.NONE,
            NmapScripts.NONE,
            ConfigScanMode.STEALTH,
        )
        assert "--max-retries" in flags and "1" in flags
        assert "--host-timeout" in flags

    def test_raid_adds_min_rate(self):
        flags = _assemble_flags(
            NmapMode.QUICK_PORTS,
            NmapBanner.NONE,
            NmapScripts.NONE,
            ConfigScanMode.RAID,
        )
        assert "--min-rate" in flags

    def test_vuln_scripts_refused_under_stealth(self):
        # Loud script bundle vs explicit stealth posture -> raise at the
        # boundary so the OA sees the refusal and dials back.
        with pytest.raises(ValueError, match=r"VULN.*STEALTH"):
            _assemble_flags(
                NmapMode.FULL_INVENTORY,
                NmapBanner.LIGHT,
                NmapScripts.VULN,
                ConfigScanMode.STEALTH,
            )

    def test_os_detect_adds_minus_o(self):
        flags = _assemble_flags(
            NmapMode.OS_DETECT,
            NmapBanner.NONE,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
        )
        assert "-O" in flags

    def test_default_scripts_maps_to_sc_bundle(self):
        # NmapScripts.DEFAULT is nmap's -sC (default NSE category),
        # composed through the uniform --script= path as --script=default.
        flags = _assemble_flags(
            NmapMode.SERVICE_VERSION,
            NmapBanner.LIGHT,
            NmapScripts.DEFAULT,
            ConfigScanMode.NORMAL,
        )
        assert "--script=default" in flags

    def test_ports_replace_top_100_with_targeted_p(self):
        # A focused port list swaps -F (top-100) for -p <csv>: the
        # Deep Scan Host case - re-scan a host's known-open ports only.
        flags = _assemble_flags(
            NmapMode.SERVICE_VERSION,
            NmapBanner.LIGHT,
            NmapScripts.DEFAULT,
            ConfigScanMode.NORMAL,
            ports=[22, 80, 443],
        )
        assert "-F" not in flags
        assert "-p" in flags
        assert flags[flags.index("-p") + 1] == "22,80,443"
        # The mode's other flags still stand.
        assert "-sV" in flags

    def test_ports_none_keeps_top_100(self):
        # Default (no ports) keeps the existing -F top-100 behaviour so
        # every current caller is unaffected.
        flags = _assemble_flags(
            NmapMode.SERVICE_VERSION,
            NmapBanner.LIGHT,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
        )
        assert "-F" in flags
        assert "-p" not in flags

    def test_empty_ports_list_keeps_top_100(self):
        # An empty list is "no targeting" - degrade to -F rather than
        # emitting a bare -p with no spec.
        flags = _assemble_flags(
            NmapMode.SERVICE_VERSION,
            NmapBanner.LIGHT,
            NmapScripts.NONE,
            ConfigScanMode.NORMAL,
            ports=[],
        )
        assert "-F" in flags
        assert "-p" not in flags
