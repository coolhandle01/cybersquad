"""tests/tools/test_http.py - unit tests for the traceable User-Agent helper
and the shared query-parameter injection helper."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest

import runtime
from config import config
from tools import http

pytestmark = pytest.mark.unit


def _server_params(url: str) -> dict[str, list[str]]:
    """Return the parameters a server parses from ``url``'s query component.

    The whole point of ``inject_query_param`` is what the *server* receives, so
    every assertion observes the built URL the way a server would: split off the
    query component and run it through ``parse_qs``. ``keep_blank_values`` keeps
    an empty value (``flag=``) as ``[""]`` instead of dropping the key, so a
    payload that legitimately injects a blank value is still observable rather
    than silently vanishing from the parse.
    """
    return parse_qs(urlsplit(url).query, keep_blank_values=True)


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


class TestInjectQueryParam:
    """The shared injection helper, observed the way a server parses it.

    Two suite-wide bugs live here, so each is pinned against the
    *server-received* value (``_server_params``), not the raw string: an
    already-present query string must never yield a second ``?`` that folds the
    payload into a prior value, and query-significant bytes in the payload must
    survive percent-encoded so the server sees the literal character.
    """

    def test_appends_to_url_with_no_query(self, target_apex):
        url = http.inject_query_param(f"https://api.{target_apex}/search", "q", "payload")
        # No pre-existing query: the pair is introduced with a single '?'.
        assert url == f"https://api.{target_apex}/search?q=payload"
        assert _server_params(url) == {"q": ["payload"]}

    def test_splices_onto_existing_query_with_ampersand(self, target_apex):
        base = f"https://api.{target_apex}/search?a=1"
        url = http.inject_query_param(base, "b", "2")
        # The bug this closes: a naive f-string would emit '...?a=1?b=2', whose
        # second '?' the server folds into a='1?b=2', so 'b' never registers.
        assert url.count("?") == 1
        assert url == f"https://api.{target_apex}/search?a=1&b=2"
        # Observed as the server parses it: both keys are present and distinct.
        assert _server_params(url) == {"a": ["1"], "b": ["2"]}

    def test_second_question_mark_bug_is_not_reintroduced(self, target_apex):
        """The existing param keeps its own value; the payload does not fold in."""
        base = f"https://api.{target_apex}/p?token=abc123"
        url = http.inject_query_param(base, "inject", "x")
        params = _server_params(url)
        # The original value is untouched - not 'abc123?inject=x'.
        assert params["token"] == ["abc123"]
        assert params["inject"] == ["x"]

    def test_preserves_multiple_existing_params(self, target_apex):
        base = f"https://api.{target_apex}/search?a=1&b=2"
        url = http.inject_query_param(base, "c", "3")
        assert url.count("?") == 1
        assert _server_params(url) == {"a": ["1"], "b": ["2"], "c": ["3"]}

    def test_duplicate_name_appends_second_value_hpp(self, target_apex):
        """An HPP probe adds a second ``p=2`` to an existing ``p=1``; both must
        survive, in order, as two values of the same key - the textual splice
        does not collapse the duplicate the way a dict merge would."""
        base = f"https://api.{target_apex}/search?p=1"
        url = http.inject_query_param(base, "p", "2")
        assert url == f"https://api.{target_apex}/search?p=1&p=2"
        assert _server_params(url) == {"p": ["1", "2"]}

    # --- The special-character round-trips: the payloads the raw f-string mangled.
    # Each asserts the SERVER-RECEIVED value equals the literal byte injected.

    def test_hash_reaches_server_and_opens_no_fragment(self, target_apex):
        """'#' raw would open a URL fragment and drop the rest of the payload
        before the request was even sent. Encoded, it reaches the server as a
        literal '#' and the built URL carries no fragment."""
        url = http.inject_query_param(f"https://api.{target_apex}/s", "q", "a#b")
        assert "#" not in url  # no literal '#' survived into the URL structure
        assert urlsplit(url).fragment == ""
        assert _server_params(url) == {"q": ["a#b"]}

    def test_plus_reaches_server_as_literal_plus_not_space(self, target_apex):
        """'+' form-decodes to a space; the payload meant a literal '+'."""
        url = http.inject_query_param(f"https://api.{target_apex}/s", "q", "a+b")
        assert _server_params(url) == {"q": ["a+b"]}

    def test_ampersand_reaches_server_without_truncating(self, target_apex):
        """'&' raw starts the next parameter, truncating the value and spawning a
        stray key. Encoded, it stays inside the one value the payload intended."""
        url = http.inject_query_param(f"https://api.{target_apex}/s", "q", "a&b=c")
        params = _server_params(url)
        assert params == {"q": ["a&b=c"]}
        # And no spurious second parameter leaked out of the payload.
        assert list(params) == ["q"]

    def test_space_reaches_server_as_literal_space(self, target_apex):
        url = http.inject_query_param(f"https://api.{target_apex}/s", "q", "a b")
        assert _server_params(url) == {"q": ["a b"]}

    def test_every_query_significant_byte_round_trips(self, target_apex):
        """A single value carrying '#', '+', '&', space, ';', '(', ')', '*' -
        the full set of query-significant bytes - survives intact end to end."""
        payload = "a#b+c&d e;f(g)h*i"
        url = http.inject_query_param(f"https://api.{target_apex}/s", "q", payload)
        assert urlsplit(url).fragment == ""
        assert _server_params(url) == {"q": [payload]}

    def test_name_is_percent_encoded_too(self, target_apex):
        """A parameter name carrying query-significant bytes is encoded as well,
        so the server parses the intended key rather than a mangled one."""
        url = http.inject_query_param(f"https://api.{target_apex}/s", "p q&r", "v")
        assert _server_params(url) == {"p q&r": ["v"]}

    def test_blank_value_is_kept(self, target_apex):
        """An injected blank value is a real injection, not a no-op; the pair is
        emitted as ``flag=`` and observed with ``keep_blank_values``."""
        url = http.inject_query_param(f"https://api.{target_apex}/s", "flag", "")
        assert url == f"https://api.{target_apex}/s?flag="
        assert _server_params(url) == {"flag": [""]}

    def test_fragment_is_preserved_and_param_lands_in_query(self, target_apex):
        """An existing fragment is kept, and the parameter is placed in the query
        component ahead of it - not appended after the fragment where the server
        would never see it."""
        url = http.inject_query_param(f"https://api.{target_apex}/s#section", "q", "v")
        split = urlsplit(url)
        assert split.fragment == "section"
        assert _server_params(url) == {"q": ["v"]}

    def test_is_pure_returns_new_string_without_side_effects(self, target_apex):
        """No request is issued and the inputs are unchanged - a pure function
        the probes can call while building a URL."""
        original = f"https://api.{target_apex}/search?a=1"
        with patch("requests.get") as mock_get, patch("requests.request") as mock_req:
            result = http.inject_query_param(original, "b", "2")
        mock_get.assert_not_called()
        mock_req.assert_not_called()
        assert isinstance(result, str)
        assert original == f"https://api.{target_apex}/search?a=1"
