"""Contract tests for the ``make_response`` shared fixture.

The fixture is test infrastructure the whole probe/recon suite leans on, so
its one behavioural guarantee - that ``raise_for_status()`` is status-aware,
faithful to a real ``requests.Response`` - is pinned here rather than left to
each consumer to rediscover. Both directions of the 400 boundary are asserted:
a guard that raised on everything, or on nothing, would be as useless here as a
scope filter that admits nothing.
"""

from __future__ import annotations

import pytest
import requests

pytestmark = pytest.mark.unit


class TestMakeResponseRaiseForStatus:
    def test_no_raise_below_400(self, make_response) -> None:
        # A real Response.raise_for_status() returns None on success; the
        # fixture must too, or every 2xx consumer that calls it would break.
        for status in (200, 201, 204, 301, 302, 399):
            resp = make_response(status=status)
            assert resp.raise_for_status() is None

    def test_raises_http_error_on_4xx(self, make_response) -> None:
        resp = make_response(status=404)
        with pytest.raises(requests.HTTPError):
            resp.raise_for_status()

    def test_raises_http_error_on_5xx(self, make_response) -> None:
        resp = make_response(status=503)
        with pytest.raises(requests.HTTPError):
            resp.raise_for_status()

    def test_boundary_400_raises(self, make_response) -> None:
        # 400 is the first raising status - the exact boundary requests draws.
        resp = make_response(status=400)
        with pytest.raises(requests.HTTPError):
            resp.raise_for_status()

    def test_default_status_does_not_raise(self, make_response) -> None:
        # The default (no status= passed) is 200, so the common case stays a
        # no-op and existing callers that never touched status are unaffected.
        assert make_response().raise_for_status() is None

    def test_error_carries_response_with_status(self, make_response) -> None:
        # `except HTTPError as e: e.response.status_code` is real calling code;
        # the raised error must carry the response, not just a bare message.
        resp = make_response(status=418)
        with pytest.raises(requests.HTTPError) as exc_info:
            resp.raise_for_status()
        assert exc_info.value.response is resp
        assert exc_info.value.response.status_code == 418

    def test_client_vs_server_error_wording(self, make_response) -> None:
        # Mirrors requests' own split so a test asserting the message stays
        # consistent whether it builds the response by hand or via the fixture.
        with pytest.raises(requests.HTTPError, match="404 Client Error"):
            make_response(status=404).raise_for_status()
        with pytest.raises(requests.HTTPError, match="503 Server Error"):
            make_response(status=503).raise_for_status()
