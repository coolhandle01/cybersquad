"""tests/tools/test_html.py - unit tests for tools/html.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tools import html

pytestmark = pytest.mark.unit


def _mock_get(body: str = "", content_type: str = "text/html; charset=utf-8") -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.text = body
    resp.headers = {"Content-Type": content_type}
    return resp


class TestFetch:
    def test_returns_response_and_soup_pair(self, target_apex) -> None:
        from bs4 import BeautifulSoup

        with patch("requests.get", return_value=_mock_get(body="<html><body>hi</body></html>")):
            resp, soup = html.fetch(f"https://{target_apex}/")

        assert isinstance(resp, MagicMock)
        assert isinstance(soup, BeautifulSoup)

    def test_soup_contains_parsed_html(self, target_apex) -> None:
        body = "<html><body><h1>Hello</h1></body></html>"
        with patch("requests.get", return_value=_mock_get(body=body)):
            _, soup = html.fetch(f"https://{target_apex}/")

        h1 = soup.find("h1")
        assert h1 is not None
        assert h1.text == "Hello"

    def test_empty_soup_for_non_html_content_type(self, target_apex) -> None:
        with patch(
            "requests.get",
            return_value=_mock_get(body='{"key": "val"}', content_type="application/json"),
        ):
            _, soup = html.fetch(f"https://{target_apex}/api")

        assert soup.find() is None

    def test_empty_soup_when_content_type_missing(self, target_apex) -> None:
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html><body>hi</body></html>"
        resp.headers = {}
        with patch("requests.get", return_value=resp):
            _, soup = html.fetch(f"https://{target_apex}/")

        assert soup.find() is None

    def test_kwargs_forwarded_to_http_get(self, target_apex) -> None:
        with patch("requests.get", return_value=_mock_get()) as mock_get:
            html.fetch(f"https://{target_apex}/", allow_redirects=True)

        assert mock_get.call_args.kwargs.get("allow_redirects") is True

    def test_caller_timeout_forwarded(self, target_apex) -> None:
        with patch("requests.get", return_value=_mock_get()) as mock_get:
            html.fetch(f"https://{target_apex}/", timeout=5)

        assert mock_get.call_args.kwargs.get("timeout") == 5

    def test_response_is_returned_unchanged(self, target_apex) -> None:
        mock_resp = _mock_get(body="<p>content</p>")
        with patch("requests.get", return_value=mock_resp):
            resp, _ = html.fetch(f"https://{target_apex}/")

        assert resp is mock_resp
