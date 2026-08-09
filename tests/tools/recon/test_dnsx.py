"""tests/tools/recon/test_dnsx.py - unit tests for tools/recon/dnsx.py."""

from __future__ import annotations

import json
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from tools.recon.dnsx import (
    _match_fingerprint,
    detect_takeover_candidates,
    resolve_ptr,
    resolve_records,
)

pytestmark = pytest.mark.unit


# Fingerprint matcher


class TestMatchFingerprint:
    def test_matches_s3(self):
        assert _match_fingerprint("bucket.s3.amazonaws.com") == "AWS S3"

    def test_matches_heroku(self):
        assert _match_fingerprint("app.herokuapp.com") == "Heroku"

    def test_matches_github_pages(self):
        assert _match_fingerprint("user.github.io") == "GitHub Pages"

    def test_matches_azure_blob(self):
        assert _match_fingerprint("store.blob.core.windows.net") == "Azure Blob Storage"

    def test_matches_case_insensitive(self):
        assert _match_fingerprint("Bucket.S3.AmazonAWS.com") == "AWS S3"

    def test_strips_trailing_dot(self):
        assert _match_fingerprint("app.herokuapp.com.") == "Heroku"

    def test_unknown_cname_returns_none(self):
        assert _match_fingerprint("some.legitimate.host.example.com") is None

    def test_empty_returns_none(self):
        assert _match_fingerprint("") is None


# resolve_records


def _completed(stdout: str) -> CompletedProcess:
    return CompletedProcess([], 0, stdout, "")


class TestResolveRecords:
    def test_empty_input_returns_empty(self):
        # Should not require the binary or call _run
        with patch("shutil.which", return_value=None):
            assert resolve_records([]) == []

    def test_parses_dnsx_json_output(self):
        out = (
            json.dumps({"host": "api.example.com", "a": ["1.2.3.4"], "cname": [], "ttl": 300})
            + "\n"
            + json.dumps(
                {
                    "host": "legacy.example.com",
                    "a": [],
                    "cname": ["legacy.example.com.s3.amazonaws.com"],
                }
            )
            + "\n"
        )
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            records = resolve_records(["api.example.com", "legacy.example.com"])

        assert {r.hostname for r in records} == {"api.example.com", "legacy.example.com"}
        api = next(r for r in records if r.hostname == "api.example.com")
        assert api.ttl == 300  # dnsx's reported response TTL is captured
        legacy = next(r for r in records if r.hostname == "legacy.example.com")
        assert legacy.cname == ["legacy.example.com.s3.amazonaws.com"]
        assert legacy.a_records == []
        assert legacy.ttl == 0  # omitted by dnsx -> defaults to 0

    def test_skips_malformed_lines(self):
        out = "not-json-at-all\n" + json.dumps({"host": "x.example.com", "a": ["1.1.1.1"]}) + "\n"
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            records = resolve_records(["x.example.com"])

        assert len(records) == 1
        assert records[0].hostname == "x.example.com"

    def test_skips_blank_lines(self):
        out = "\n\n" + json.dumps({"host": "y.example.com", "a": ["1.1.1.1"]}) + "\n"
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            assert len(resolve_records(["y.example.com"])) == 1

    def test_drops_entries_with_no_host(self):
        out = json.dumps({"a": ["1.1.1.1"]}) + "\n"
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            assert resolve_records(["nohost.example.com"]) == []

    def test_whitespace_only_input_returns_empty(self):
        with patch("shutil.which", return_value="/usr/bin/dnsx") as mwhich:
            assert resolve_records(["  ", ""]) == []
            mwhich.assert_called_once()


# detect_takeover_candidates


class TestDetectTakeoverCandidates:
    def test_flags_cname_to_vulnerable_provider(self):
        out = json.dumps(
            {
                "host": "legacy.example.com",
                "a": ["52.0.0.1"],
                "cname": ["bucket.s3.amazonaws.com"],
            }
        )
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            candidates = detect_takeover_candidates(["legacy.example.com"])

        assert len(candidates) == 1
        c = candidates[0]
        assert c.hostname == "legacy.example.com"
        assert c.reason == "cname_to_vulnerable_provider"
        assert c.service == "AWS S3"
        assert c.cname == "bucket.s3.amazonaws.com"

    def test_flags_dangling_cname(self):
        # CNAME exists but no A records
        out = json.dumps(
            {
                "host": "abandoned.example.com",
                "a": [],
                "cname": ["abandoned.internal.tld"],
            }
        )
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            candidates = detect_takeover_candidates(["abandoned.example.com"])

        assert len(candidates) == 1
        assert candidates[0].reason == "dangling_cname"
        assert candidates[0].service is None

    def test_does_not_flag_resolved_unknown_cname(self):
        # CNAME exists and resolves; not a known-vulnerable provider
        out = json.dumps(
            {
                "host": "alias.example.com",
                "a": ["10.0.0.1"],
                "cname": ["primary.example.com"],
            }
        )
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            assert detect_takeover_candidates(["alias.example.com"]) == []

    def test_does_not_flag_plain_a_record(self):
        # No CNAME at all - just a plain A record
        out = json.dumps({"host": "api.example.com", "a": ["1.2.3.4"], "cname": []})
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            assert detect_takeover_candidates(["api.example.com"]) == []

    def test_provider_match_takes_priority_over_dangling(self):
        # If a CNAME matches a fingerprint, that's the candidate we surface,
        # not "dangling" (even if A records are also empty).
        out = json.dumps(
            {
                "host": "legacy.example.com",
                "a": [],
                "cname": ["legacy.example.com.s3.amazonaws.com"],
            }
        )
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            candidates = detect_takeover_candidates(["legacy.example.com"])

        assert len(candidates) == 1
        assert candidates[0].reason == "cname_to_vulnerable_provider"
        assert candidates[0].service == "AWS S3"

    def test_one_candidate_per_host_on_multiple_cname_matches(self):
        # Defensive: if a single host has multiple CNAMEs and both match
        # vulnerable providers, the first one is surfaced. (Real-world DNS
        # rarely returns multiple CNAMEs for a single host, but the loop
        # handles it.)
        out = json.dumps(
            {
                "host": "double.example.com",
                "a": [],
                "cname": ["x.s3.amazonaws.com", "y.herokuapp.com"],
            }
        )
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            candidates = detect_takeover_candidates(["double.example.com"])

        assert len(candidates) == 1

    def test_empty_input_returns_empty(self):
        with patch("shutil.which", return_value=None):
            assert detect_takeover_candidates([]) == []


class TestResolveRecordsScanModeFlags:
    """The -rate-limit / -t caps flow through from config.scan.

    Patches the singleton via dnsx.py's import alias so the test stays
    robust to ``TestAdaptiveSleep``'s ``reload_module(config)``.
    """

    def test_passes_rate_limit_and_threads_from_config(self, monkeypatch):
        import tools.recon.dnsx as dnsx_mod

        monkeypatch.setattr(dnsx_mod.config.scan, "dnsx_rate_limit", 42)
        monkeypatch.setattr(dnsx_mod.config.scan, "dnsx_threads", 9)
        captured: list[list[str]] = []

        def fake_run(cmd, timeout: int = 60, input: str | None = None) -> CompletedProcess:
            captured.append(cmd)
            return CompletedProcess(cmd, 0, "", "")

        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", side_effect=fake_run),
        ):
            resolve_records(["api.example.com"])

        assert captured, "expected dnsx to be invoked"
        argv = captured[0]
        assert argv[argv.index("-rate-limit") + 1] == "42"
        assert argv[argv.index("-t") + 1] == "9"


class TestResolvePtr:
    def test_empty_input_returns_empty(self):
        with patch("shutil.which", return_value=None):
            assert resolve_ptr([]) == []

    def test_parses_ptr_json_output(self):
        out = (
            json.dumps({"host": "8.8.8.8", "ptr": ["dns.google."]})
            + "\n"
            + json.dumps({"host": "1.1.1.1", "ptr": ["one.one.one.one"]})
            + "\n"
        )
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            records = resolve_ptr(["8.8.8.8", "1.1.1.1"])

        assert len(records) == 2
        by_ip = {r.ip: r for r in records}
        # Trailing dot from the DNS wire format gets stripped.
        assert by_ip["8.8.8.8"].hostnames == ["dns.google"]
        assert by_ip["1.1.1.1"].hostnames == ["one.one.one.one"]

    def test_skips_malformed_lines(self):
        out = "this is not json\n" + json.dumps({"host": "8.8.8.8", "ptr": ["dns.google"]}) + "\n"
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            records = resolve_ptr(["8.8.8.8"])
        assert len(records) == 1

    def test_skips_blank_lines(self):
        out = "\n" + json.dumps({"host": "8.8.8.8", "ptr": ["dns.google"]}) + "\n\n"
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            records = resolve_ptr(["8.8.8.8"])
        assert len(records) == 1

    def test_drops_entries_with_no_host(self):
        out = json.dumps({"ptr": ["orphan.example.com"]}) + "\n"
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            assert resolve_ptr(["8.8.8.8"]) == []

    def test_drops_entries_where_ptr_is_not_list(self):
        out = json.dumps({"host": "8.8.8.8", "ptr": "not a list"}) + "\n"
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            assert resolve_ptr(["8.8.8.8"]) == []

    def test_filters_non_string_hostnames(self):
        # Defence: hostname list with mixed types - non-strings dropped
        # but the record itself still lands with the string entries.
        out = json.dumps({"host": "8.8.8.8", "ptr": ["dns.google", 42, None]}) + "\n"
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            records = resolve_ptr(["8.8.8.8"])
        assert len(records) == 1
        assert records[0].hostnames == ["dns.google"]

    def test_whitespace_only_input_returns_empty(self):
        with patch("shutil.which", return_value="/usr/bin/dnsx"):
            assert resolve_ptr(["   ", " "]) == []

    def test_subprocess_failure_returns_empty(self):
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", side_effect=OSError("dnsx died")),
        ):
            assert resolve_ptr(["8.8.8.8"]) == []

    def test_malformed_hostname_degrades_to_ip_only_record(self):
        # A PTR hostname that trips the FQDN validator (e.g. embedded
        # whitespace) drops the hostnames but keeps the IP signal.
        out = json.dumps({"host": "8.8.8.8", "ptr": ["not a valid hostname"]}) + "\n"
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            records = resolve_ptr(["8.8.8.8"])
        assert len(records) == 1
        assert records[0].ip == "8.8.8.8"
        assert records[0].hostnames == []

    def test_invalid_ip_in_response_drops_the_row(self):
        # If the "host" field isn't a valid IP, the IpAddr validator
        # rejects it on both the original and degraded retry - row drops.
        out = json.dumps({"host": "not.an.ip", "ptr": ["x.example.com"]}) + "\n"
        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", return_value=_completed(out)),
        ):
            assert resolve_ptr(["8.8.8.8"]) == []

    def test_passes_rate_limit_and_threads_from_config(self, monkeypatch):
        """PTR lookup picks the same dnsx caps off ``config.scan``."""
        import tools.recon.dnsx as dnsx_mod

        monkeypatch.setattr(dnsx_mod.config.scan, "dnsx_rate_limit", 11)
        monkeypatch.setattr(dnsx_mod.config.scan, "dnsx_threads", 3)
        captured: list[list[str]] = []

        def fake_run(cmd, timeout: int = 60, input: str | None = None) -> CompletedProcess:
            captured.append(cmd)
            return CompletedProcess(cmd, 0, "", "")

        with (
            patch("shutil.which", return_value="/usr/bin/dnsx"),
            patch("tools.recon.dnsx._run", side_effect=fake_run),
        ):
            resolve_ptr(["8.8.8.8"])

        assert captured, "expected dnsx PTR to be invoked"
        argv = captured[0]
        assert argv[argv.index("-rate-limit") + 1] == "11"
        assert argv[argv.index("-t") + 1] == "3"
