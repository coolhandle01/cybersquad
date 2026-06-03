"""tests/tools/recon/test_asn.py - unit tests for Team Cymru bulk-whois wrapper.

Covers the row parser (``_parse_cymru_row``) and the ``lookup_asn``
orchestrator. All subprocess invocations are mocked; no live whois
queries during tests.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from models.asset.network import AsnRecord
from tools.recon.asn import _build_bulk_input, _parse_cymru_row, lookup_asn

pytestmark = pytest.mark.unit


# Real-shape sample from Cymru's verbose bulk-whois output. Two-space
# padding around pipes is how the service formats its rows.
_CYMRU_SAMPLE = """Bulk mode; verbose [2024-01-01 12:00:00 +0000]
AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name
15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 1992-12-01 | GOOGLE, US
13335   | 1.1.1.1          | 1.1.1.0/24          | US | arin     | 2010-07-14 | CLOUDFLARENET, US
"""


class TestParseCymruRow:
    def test_parses_canonical_row(self):
        line = (
            "15169   | 8.8.8.8          | 8.8.8.0/24          | US |"
            " arin     | 1992-12-01 | GOOGLE, US"
        )
        record = _parse_cymru_row(line)
        assert record is not None
        assert record.asn == 15169
        assert record.ip == "8.8.8.8"
        assert record.prefix == "8.8.8.0/24"
        assert record.country == "US"
        assert record.organisation == "GOOGLE, US"

    def test_parses_ipv6_row(self):
        line = (
            "15169   | 2001:4860:4860::8888 | 2001:4860::/32      | US |"
            " arin     | 1992-12-01 | GOOGLE, US"
        )
        record = _parse_cymru_row(line)
        assert record is not None
        assert record.ip == "2001:4860:4860::8888"
        assert record.prefix == "2001:4860::/32"

    @pytest.mark.parametrize(
        "header",
        [
            (
                "AS      | IP               | BGP Prefix          | CC |"
                " Registry | Allocated  | AS Name"
            ),
            "Bulk mode; verbose [2024-01-01 12:00:00 +0000]",
            "",
            "   ",
        ],
    )
    def test_skips_header_and_blank_rows(self, header):
        assert _parse_cymru_row(header) is None

    def test_skips_rows_with_too_few_columns(self):
        # Truncated row (5 columns instead of 7) returns None rather than
        # raising - the parser is defensive against partial Cymru output.
        line = "15169   | 8.8.8.8 | 8.8.8.0/24 | US | arin"
        assert _parse_cymru_row(line) is None

    def test_skips_rows_with_non_numeric_asn(self):
        # "NA" appears when Cymru doesn't know the ASN (RFC 1918 space,
        # unannounced ranges). Skip rather than coerce to 0.
        line = "NA      | 10.0.0.1         | NA                  | NA | NA       | NA         | NA"
        assert _parse_cymru_row(line) is None

    def test_skips_rows_with_invalid_ip(self):
        # Malformed IP value (validator rejects); whole row dropped.
        line = (
            "15169   | not-an-ip        | 8.8.8.0/24          | US |"
            " arin     | 1992-12-01 | GOOGLE, US"
        )
        assert _parse_cymru_row(line) is None


class TestBuildBulkInput:
    def test_wraps_with_envelope(self):
        body = _build_bulk_input(["8.8.8.8", "1.1.1.1"])
        assert body.startswith("begin\nverbose\n")
        assert body.endswith("end\n")
        assert "8.8.8.8" in body
        assert "1.1.1.1" in body

    def test_empty_list_still_valid_envelope(self):
        body = _build_bulk_input([])
        assert "begin" in body and "end" in body


class TestLookupAsn:
    def test_returns_records_for_known_ips(self, monkeypatch):
        from unittest.mock import MagicMock

        result = MagicMock(stdout=_CYMRU_SAMPLE, returncode=0)
        with (
            patch("tools.recon.asn._require_binary", return_value="/usr/bin/whois"),
            patch("tools.recon.asn._run", return_value=result),
        ):
            records = lookup_asn(["8.8.8.8", "1.1.1.1"])
        assert len(records) == 2
        assert {r.asn for r in records} == {15169, 13335}
        assert {r.ip for r in records} == {"8.8.8.8", "1.1.1.1"}
        assert all(isinstance(r, AsnRecord) for r in records)

    def test_empty_input_returns_empty(self):
        # No whois invocation should happen; short-circuit at the top.
        with patch("tools.recon.asn._require_binary") as mock_bin:
            assert lookup_asn([]) == []
        mock_bin.assert_not_called()

    def test_subprocess_failure_returns_empty(self):
        # Network down / whois binary missing -> degrade gracefully to
        # empty list rather than raising; recon should keep running with
        # whatever signal IS available.
        with (
            patch("tools.recon.asn._require_binary", return_value="/usr/bin/whois"),
            patch("tools.recon.asn._run", side_effect=OSError("network down")),
        ):
            assert lookup_asn(["8.8.8.8"]) == []

    def test_unknown_ips_drop_silently(self):
        # Cymru's "NA" response for unknown IPs - the parser drops them;
        # the lookup returns an empty list when nothing resolves.
        from unittest.mock import MagicMock

        na_response = """Bulk mode; verbose
NA      | 10.0.0.1         | NA                  | NA | NA       | NA         | NA
"""
        result = MagicMock(stdout=na_response, returncode=0)
        with (
            patch("tools.recon.asn._require_binary", return_value="/usr/bin/whois"),
            patch("tools.recon.asn._run", return_value=result),
        ):
            assert lookup_asn(["10.0.0.1"]) == []

    def test_batches_oversized_input(self):
        # Calls > _MAX_BATCH IPs split into multiple subprocess invocations.
        # Use 300 IPs (well over the 256 cap) and assert _run is called
        # twice with disjoint chunks.
        from unittest.mock import MagicMock

        from tools.recon.asn import _MAX_BATCH

        ips = [f"10.0.0.{i % 254 + 1}" for i in range(_MAX_BATCH + 50)]
        result = MagicMock(stdout="", returncode=0)
        with (
            patch("tools.recon.asn._require_binary", return_value="/usr/bin/whois"),
            patch("tools.recon.asn._run", return_value=result) as mock_run,
        ):
            lookup_asn(ips)
        assert mock_run.call_count == 2
