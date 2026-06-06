"""tests/tools/recon/httpx/test_flags.py - unit tests for tools/recon/httpx/flags.py."""

from __future__ import annotations

import pytest

from models.scanner import HttpxMode
from tools.recon.httpx.flags import _assemble_flags

pytestmark = pytest.mark.unit


class TestAssembleFlags:
    def test_live_minimal(self):
        flags = _assemble_flags(HttpxMode.LIVE)
        assert "-silent" in flags
        assert "-json" in flags
        assert "-status-code" in flags
        # The tech-detect-bundle flags do NOT appear at LIVE mode.
        assert "-tech-detect" not in flags
        assert "-favicon" not in flags
        assert "-tls-grab" not in flags

    def test_tech_detect_adds_signal_flags(self):
        flags = _assemble_flags(HttpxMode.TECH_DETECT)
        assert "-tech-detect" in flags
        assert "-server" in flags
        assert "-title" in flags
        # The web-inventory-only flags stay absent.
        assert "-favicon" not in flags
        assert "-tls-grab" not in flags

    def test_web_inventory_adds_favicon_and_tls(self):
        flags = _assemble_flags(HttpxMode.WEB_INVENTORY)
        # Everything tech-detect has, plus the heavy flags.
        assert "-tech-detect" in flags
        assert "-favicon" in flags
        assert "-tls-grab" in flags
        assert "-content-type" in flags
        assert "-method" in flags

    def test_timeout_always_present(self):
        for mode in HttpxMode:
            flags = _assemble_flags(mode)
            assert "-timeout" in flags

    def test_rate_retries_threads_from_scan_config(self, monkeypatch):
        """httpx picks ``-rate-limit`` / ``-retries`` / ``-threads`` off
        ``config.scan`` so the operator's stealth dial flows through.

        Patches the singleton via the same import alias ``flags.py``
        binds. ``TestAdaptiveSleep`` reloads ``config``, leaving older
        modules referencing the pre-reload singleton; targeting the
        consumer's alias makes the patch robust to that.
        """
        from tools.recon.httpx import flags as httpx_flags

        monkeypatch.setattr(httpx_flags.config.scan, "httpx_rate_limit", 13)
        monkeypatch.setattr(httpx_flags.config.scan, "httpx_retries", 4)
        monkeypatch.setattr(httpx_flags.config.scan, "httpx_threads", 7)
        flags = _assemble_flags(HttpxMode.LIVE)
        assert flags[flags.index("-rate-limit") + 1] == "13"
        assert flags[flags.index("-retries") + 1] == "4"
        assert flags[flags.index("-threads") + 1] == "7"

    def test_rate_retries_threads_present_in_every_mode(self):
        """The caps apply to every mode, not just LIVE."""
        for mode in HttpxMode:
            flags = _assemble_flags(mode)
            assert "-rate-limit" in flags, f"{mode.value} missing -rate-limit"
            assert "-retries" in flags, f"{mode.value} missing -retries"
            assert "-threads" in flags, f"{mode.value} missing -threads"

    def test_no_overlapping_recon_flags(self):
        # Skipping -asn (defers to asn.py / Cymru) and -cname (defers
        # to dnsx). Pin the omission so a future "let's just throw all
        # the httpx flags in" patch can't sneak them past review.
        for mode in HttpxMode:
            flags = _assemble_flags(mode)
            assert "-asn" not in flags, f"-asn appears in {mode.value} mode"
            assert "-cname" not in flags, f"-cname appears in {mode.value} mode"

    def test_screenshot_toggle_adds_evidence_flags(self):
        flags = _assemble_flags(
            HttpxMode.WEB_INVENTORY,
            with_screenshots=True,
            evidence_dir="/tmp/evidence",
        )
        assert "-screenshot" in flags
        assert "-srd" in flags
        # -srd takes the directory as its argument.
        assert flags[flags.index("-srd") + 1] == "/tmp/evidence"
        # -store-response NOT requested -> absent.
        assert "-store-response" not in flags

    def test_responses_toggle_adds_store_response(self):
        flags = _assemble_flags(
            HttpxMode.TECH_DETECT,
            with_responses=True,
            evidence_dir="/tmp/evidence",
        )
        assert "-store-response" in flags
        assert "-srd" in flags
        assert "-screenshot" not in flags

    def test_evidence_flags_omitted_when_dir_is_none(self):
        # Toggles set but no evidence_dir bound (no pipeline run) -> the
        # scan still runs, just no file-on-disk evidence flags.
        flags = _assemble_flags(
            HttpxMode.WEB_INVENTORY,
            with_screenshots=True,
            with_responses=True,
            evidence_dir=None,
        )
        assert "-screenshot" not in flags
        assert "-store-response" not in flags
        assert "-srd" not in flags
