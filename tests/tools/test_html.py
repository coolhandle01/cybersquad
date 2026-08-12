"""tests/tools/test_html.py - unit tests for ``html.fetch()``.

The ``Webpage`` class tests live in ``test_webpage.py``; this file just
covers the thin ``fetch(url, **kwargs)`` entry point that wraps
``http.get`` + the Webpage constructor.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tools import html

pytestmark = pytest.mark.unit

_HTML_CT = {"Content-Type": "text/html; charset=utf-8"}
_JSON_CT = {"Content-Type": "application/json"}


class TestFetch:
    def test_returns_webpage_with_response_and_soup(self, target_apex, make_response) -> None:
        from bs4 import BeautifulSoup

        resp = make_response(body="<html><body>hi</body></html>", headers=_HTML_CT)
        with patch("requests.get", return_value=resp):
            page = html.fetch(f"https://{target_apex}/")

        assert isinstance(page, html.Webpage)
        assert isinstance(page.response, MagicMock)
        assert isinstance(page.soup, BeautifulSoup)

    def test_soup_contains_parsed_html(self, target_apex, make_response) -> None:
        body = "<html><body><h1>Hello</h1></body></html>"
        with patch("requests.get", return_value=make_response(body=body, headers=_HTML_CT)):
            page = html.fetch(f"https://{target_apex}/")

        h1 = page.soup.find("h1")
        assert h1 is not None
        assert h1.text == "Hello"

    def test_empty_soup_for_non_html_content_type(self, target_apex, make_response) -> None:
        resp = make_response(body='{"key": "val"}', headers=_JSON_CT)
        with patch("requests.get", return_value=resp):
            page = html.fetch(f"https://{target_apex}/api")

        assert page.soup.find() is None

    def test_empty_soup_when_content_type_missing(self, target_apex, make_response) -> None:
        resp = make_response(body="<html><body>hi</body></html>", headers={})
        with patch("requests.get", return_value=resp):
            page = html.fetch(f"https://{target_apex}/")

        assert page.soup.find() is None

    def test_kwargs_forwarded_to_http_get(self, target_apex, make_response) -> None:
        with patch("requests.get", return_value=make_response()) as mock_get:
            html.fetch(f"https://{target_apex}/", allow_redirects=True)

        assert mock_get.call_args.kwargs.get("allow_redirects") is True

    def test_caller_timeout_forwarded(self, target_apex, make_response) -> None:
        with patch("requests.get", return_value=make_response()) as mock_get:
            html.fetch(f"https://{target_apex}/", timeout=5)

        assert mock_get.call_args.kwargs.get("timeout") == 5

    def test_response_is_returned_unchanged(self, target_apex, make_response) -> None:
        mock_resp = make_response(body="<p>content</p>", headers=_HTML_CT)
        with patch("requests.get", return_value=mock_resp):
            page = html.fetch(f"https://{target_apex}/")

        assert page.response is mock_resp
