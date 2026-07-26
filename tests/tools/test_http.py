"""tests/tools/test_http.py - unit tests for the traceable User-Agent helper."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import runtime
from config import config
from tools import http

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_runtime_programme():
    """Each test starts with no programme set and leaves it that way.

    The User-Agent reads ``runtime.programme_handle`` directly, so the
    fixture only has to keep that module-level state clean between
    tests; there is no per-request registry to reset.
    """
    saved = runtime.programme_handle
    runtime.programme_handle = ""
    yield
    runtime.programme_handle = saved


class TestUserAgent:
    def test_includes_platform_researcher_and_contact(self):
        ua = http.user_agent()
        assert ua.startswith("cybersquad (authorised research;")
        assert "platform: hackerone" in ua
        # H1 username and contact email come from config (seeded by conftest)
        assert "researcher: ci-user" in ua
        assert "contact: ci@example.invalid" in ua

    def test_omits_programme_when_unset(self):
        assert "programme:" not in http.user_agent()

    def test_includes_programme_from_runtime(self):
        """The handle the PM saved propagates without a per-tool setter call."""
        runtime.programme_handle = "acme-corp"
        assert "programme: acme-corp" in http.user_agent()


class TestInjectHeaders:
    def test_adds_user_agent_when_absent(self):
        kwargs: dict = {}
        out = http._inject_headers(kwargs)
        assert out["headers"]["User-Agent"] == http.user_agent()

    def test_preserves_existing_user_agent(self):
        kwargs = {"headers": {"User-Agent": "custom-ua"}}
        out = http._inject_headers(kwargs)
        assert out["headers"]["User-Agent"] == "custom-ua"

    def test_preserves_existing_user_agent_case_insensitive(self):
        kwargs = {"headers": {"user-agent": "custom-ua"}}
        out = http._inject_headers(kwargs)
        # The merged headers are a ``CaseInsensitiveDict``; the caller's
        # lower-cased ``user-agent`` and our canonical ``User-Agent`` are
        # the same key, so the caller's value wins and no duplicate is
        # shipped. Both lookups return the same caller-supplied value.
        assert out["headers"]["User-Agent"] == "custom-ua"
        assert out["headers"]["user-agent"] == "custom-ua"

    def test_merges_with_other_headers(self):
        kwargs = {"headers": {"Origin": "https://x"}}
        out = http._inject_headers(kwargs)
        assert out["headers"]["Origin"] == "https://x"
        assert "User-Agent" in out["headers"]

    def test_handles_no_headers_kwarg(self):
        kwargs: dict = {}
        out = http._inject_headers(kwargs)
        assert "User-Agent" in out["headers"]

    def test_duplicate_case_variants_dedupe(self):
        """Caller passes both ``User-Agent`` and ``user-agent``;
        the ``CaseInsensitiveDict`` merge dedupes by lower-cased key
        so only one survives. RFC 9110 section 5.1 makes header field
        names case-insensitive; the safe default never accidentally
        ships duplicates. Header-mutation probes that NEED literal
        duplicates work around this default deliberately."""
        kwargs = {"headers": {"User-Agent": "first", "user-agent": "second"}}
        out = http._inject_headers(kwargs)
        # Dict construction overwrites in source order, so the second
        # write wins regardless of case; the value that ships is
        # well-defined (not order-dependent on the underlying transport).
        assert len(out["headers"]) == 1
        assert out["headers"]["User-Agent"] == "second"


class TestVerbWrappers:
    def test_get_calls_requests_get_with_ua(self, target_apex):
        with patch("requests.get", return_value=MagicMock()) as mock_get:
            http.get(f"https://x.{target_apex}/")
        kwargs = mock_get.call_args.kwargs
        assert kwargs["headers"]["User-Agent"] == http.user_agent()

    def test_default_timeout_applied_when_omitted(self, target_apex):
        with patch("requests.get", return_value=MagicMock()) as mock_get:
            http.get(f"https://x.{target_apex}/")
        assert mock_get.call_args.kwargs["timeout"] == config.recon.http_timeout

    def test_explicit_timeout_not_overridden(self, target_apex):
        with patch("requests.get", return_value=MagicMock()) as mock_get:
            http.get(f"https://x.{target_apex}/", timeout=999)
        assert mock_get.call_args.kwargs["timeout"] == 999

    def test_post_calls_requests_post_with_ua(self, target_apex):
        with patch("requests.post", return_value=MagicMock()) as mock_post:
            http.post(f"https://x.{target_apex}/", json={"a": 1})
        kwargs = mock_post.call_args.kwargs
        assert kwargs["headers"]["User-Agent"] == http.user_agent()
        assert kwargs["json"] == {"a": 1}

    @pytest.mark.parametrize("verb", ["put", "delete", "head", "patch", "options"])
    def test_other_verbs_inject_ua(self, verb, target_apex):
        with patch(f"requests.{verb}", return_value=MagicMock()) as mock_call:
            getattr(http, verb)(f"https://x.{target_apex}/")
        assert mock_call.call_args.kwargs["headers"]["User-Agent"] == http.user_agent()

    def test_request_passes_method(self, target_apex):
        with patch("requests.request", return_value=MagicMock()) as mock_req:
            http.request("PATCH", f"https://x.{target_apex}/")
        args, kwargs = mock_req.call_args
        assert args[0] == "PATCH"
        assert kwargs["headers"]["User-Agent"] == http.user_agent()

    def test_programme_appears_in_outbound_ua(self, target_apex):
        """A programme set on ``runtime`` rides every outbound request."""
        runtime.programme_handle = "acme-corp"
        with patch("requests.get", return_value=MagicMock()) as mock_get:
            http.get(f"https://x.{target_apex}/")
        ua = mock_get.call_args.kwargs["headers"]["User-Agent"]
        assert "programme: acme-corp" in ua
