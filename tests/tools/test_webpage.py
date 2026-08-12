"""tests/tools/test_webpage.py - unit tests for the ``Webpage`` shape in tools/html.py.

Split out of ``test_html.py`` (which now just covers the ``html.fetch()``
function itself) - the Webpage class earns its own file so adding a new
recipe to it (scripts / stylesheets / future SubResource kinds) does not
inflate the fetch-test file alongside.
"""

from __future__ import annotations

import pytest

from models.framework import Framework
from tools import html

pytestmark = pytest.mark.unit

_HTML_CT = {"Content-Type": "text/html; charset=utf-8"}


@pytest.fixture
def make_page(make_response, target_apex):
    """Build a Webpage from a soup body + optional cookies / url overrides.

    Single source of truth across the Webpage test classes - avoids the
    "three slightly-different _page helpers" trap. ``body`` always lands
    on ``response.text`` AND is the HTML the soup is parsed from, so
    response and soup stay consistent. The default page URL derives from
    ``target_apex`` so the suite's single-knob retargeting still holds.
    """

    def _build(
        body: str = "",
        cookies: dict | None = None,
        url: str | None = None,
    ) -> html.Webpage:
        resolved_url = url if url is not None else f"https://{target_apex}/"
        resp = make_response(body=body, headers=_HTML_CT, cookies=cookies, url=resolved_url)
        return html.Webpage(response=resp)

    return _build


class TestWebpageCsrfSignals:
    """Cookie- and meta-tag-based CSRF protection detection."""

    @pytest.mark.parametrize(
        "cookies",
        [
            {"csrftoken": "abc"},  # Django
            {"XSRF-TOKEN": "abc"},  # Angular / Laravel
            {"_xsrf": "abc"},  # Tornado
            {"xsrf-token": "abc"},  # case-insensitive match
        ],
    )
    def test_has_csrf_cookie_true(self, make_page, cookies) -> None:
        assert make_page(cookies=cookies).has_csrf_cookie()

    @pytest.mark.parametrize(
        "cookies",
        [
            None,
            {"sessionid": "abc"},
            {"JSESSIONID": "abc"},
        ],
    )
    def test_has_csrf_cookie_false(self, make_page, cookies) -> None:
        assert not make_page(cookies=cookies).has_csrf_cookie()

    @pytest.mark.parametrize(
        "body",
        [
            '<meta name="csrf-token" content="abc">',  # Rails / Spring
            '<meta name="_csrf" content="abc">',
            '<meta name="xsrf-token" content="abc">',
            '<meta name="CSRF-Token" content="abc">',  # case-insensitive
        ],
    )
    def test_has_csrf_meta_tag_true(self, make_page, body) -> None:
        assert make_page(body=body).has_csrf_meta_tag()

    @pytest.mark.parametrize(
        "body",
        [
            "<html></html>",
            '<meta name="description" content="abc">',
            '<meta name="viewport" content="width=device-width">',
        ],
    )
    def test_has_csrf_meta_tag_false(self, make_page, body) -> None:
        assert not make_page(body=body).has_csrf_meta_tag()

    def test_page_protected_true_via_cookie(self, make_page) -> None:
        assert make_page(cookies={"csrftoken": "abc"}).page_protected

    def test_page_protected_true_via_meta(self, make_page) -> None:
        assert make_page(body='<meta name="csrf-token" content="abc">').page_protected

    def test_page_protected_false_when_neither(self, make_page) -> None:
        assert not make_page(body="<html></html>").page_protected


class TestWebpageFrameworks:
    """High-confidence Framework detection via cookies + meta tags + URL patterns."""

    @pytest.mark.parametrize(
        ("cookies", "body", "expected"),
        [
            # Unambiguous cookie signals
            ({"csrftoken": "abc"}, "", {Framework.django}),
            ({"_xsrf": "abc"}, "", {Framework.tornado}),
            # Unambiguous meta signal
            (None, '<meta name="csrf-param" content="auth_token">', {Framework.rails}),
            # Ambiguous - typed channel stays empty even though page_protected flips
            ({"XSRF-TOKEN": "abc"}, "", set()),
            (None, '<meta name="csrf-token" content="abc">', set()),
            # No signals
            (None, "<html></html>", set()),
        ],
    )
    def test_detection(self, make_page, cookies, body, expected) -> None:
        page = make_page(body=body, cookies=cookies)
        assert page.frameworks == expected

    def test_ambiguous_signals_still_drive_page_protected(self, make_page) -> None:
        # XSRF-TOKEN (Angular OR Laravel) emits no typed Framework but
        # still raises the page_protected flag - the suppression rule in
        # CSRF Tier 1 depends on this.
        page = make_page(cookies={"XSRF-TOKEN": "abc"})
        assert page.frameworks == set()
        assert page.page_protected

    @pytest.mark.parametrize(
        ("body_template", "expected"),
        [
            # Modern Angular - scoped npm package on a CDN
            (
                '<script src="{cdn}/@angular/core@17/main.js"></script>',
                {Framework.angular},
            ),
            # Modern Angular - zone.js runtime (relative path)
            ('<script src="/zone.js"></script>', {Framework.angular}),
            # Legacy AngularJS - on a CDN
            ('<script src="{cdn}/angular.js"></script>', {Framework.angularjs}),
            ('<script src="{cdn}/angular.min.js"></script>', {Framework.angularjs}),
            # React
            ('<script src="/static/react.production.min.js"></script>', {Framework.react}),
            ('<script src="/static/react-dom.js"></script>', {Framework.react}),
            # Vue
            ('<script src="/static/vue.min.js"></script>', {Framework.vue}),
            # Next.js
            ('<script src="/_next/static/chunks/main.js"></script>', {Framework.nextjs}),
            # Bootstrap CSS
            (
                '<link rel="stylesheet" href="/static/bootstrap.min.css">',
                {Framework.bootstrap},
            ),
            # Bootstrap JS
            ('<script src="/static/bootstrap.bundle.js"></script>', {Framework.bootstrap}),
            # No JS framework signal
            ('<script src="/app.js"></script>', set()),
        ],
    )
    def test_detection_from_script_and_link_urls(
        self, make_page, bystander_url, body_template, expected
    ) -> None:
        page = make_page(body=body_template.format(cdn=bystander_url))
        assert page.frameworks == expected

    def test_multiple_frameworks_detected(self, make_page) -> None:
        # A React + Bootstrap page should report both.
        page = make_page(
            body=(
                '<script src="/static/react.production.min.js"></script>'
                '<link rel="stylesheet" href="/static/bootstrap.min.css">'
            ),
        )
        assert page.frameworks == {Framework.react, Framework.bootstrap}

    def test_url_detection_is_case_insensitive(self, make_page) -> None:
        page = make_page(body='<script src="/static/REACT.JS"></script>')
        # URL substring match is case-insensitive; "/react." matches.
        assert Framework.react in page.frameworks


class TestWebpageFavicon:
    """Favicon URL extraction (for Shodan / Censys favicon-hash lookup)."""

    def test_explicit_icon_link(self, make_page, target_apex) -> None:
        page = make_page(body='<link rel="icon" href="/static/icon.png">')
        assert page.favicon == f"https://{target_apex}/static/icon.png"

    def test_shortcut_icon_rel(self, make_page, target_apex) -> None:
        # Old "shortcut icon" rel value - BeautifulSoup splits rel into a list,
        # so both "shortcut" and "icon" appear and we still recognise it.
        page = make_page(body='<link rel="shortcut icon" href="/old.ico">')
        assert page.favicon == f"https://{target_apex}/old.ico"

    def test_absolute_href_unchanged(self, make_page, bystander_url) -> None:
        page = make_page(
            body=f'<link rel="icon" href="{bystander_url}/favicon.png">',
        )
        assert page.favicon == f"{bystander_url}/favicon.png"

    def test_fallback_to_origin_favicon_ico(self, make_page, target_apex) -> None:
        # No explicit link -> browser falls back to /favicon.ico, we mirror that.
        page = make_page(body="<html></html>")
        assert page.favicon == f"https://{target_apex}/favicon.ico"

    def test_ignores_apple_touch_icon(self, make_page, target_apex) -> None:
        # apple-touch-icon is a sibling but distinct rel - not a favicon.
        page = make_page(
            body='<link rel="apple-touch-icon" href="/apple.png">',
        )
        assert page.favicon == f"https://{target_apex}/favicon.ico"

    def test_cached(self, make_page) -> None:
        page = make_page(body='<link rel="icon" href="/icon.png">')
        assert page.favicon == page.favicon


class TestWebpageForms:
    """Form parsing on the Webpage shape."""

    def test_post_forms_picks_only_post(self, make_page) -> None:
        page = make_page(
            body=(
                '<form method="get" action="/search"></form>'
                '<form method="post" action="/submit"></form>'
            ),
        )
        assert len(page.post_forms) == 1
        assert page.post_forms[0].action == "/submit"

    def test_get_forms_picks_only_get(self, make_page) -> None:
        page = make_page(
            body=(
                '<form method="get" action="/search"></form>'
                '<form method="post" action="/submit"></form>'
            ),
        )
        assert len(page.get_forms) == 1
        assert page.get_forms[0].action == "/search"

    def test_default_method_is_get(self, make_page) -> None:
        page = make_page(body='<form action="/x"></form>')
        assert page.forms[0].method == "get"
        assert page.get_forms == page.forms
        assert page.post_forms == []

    @pytest.mark.parametrize(
        ("action_template", "expected_template"),
        [
            ("/submit", "https://{apex}/submit"),
            ("", "https://{apex}/page"),
            ("{bystander}/x", "{bystander}/x"),
        ],
    )
    def test_resolved_action(
        self,
        make_page,
        target_apex,
        bystander_url,
        action_template,
        expected_template,
    ) -> None:
        action_attr = action_template.format(bystander=bystander_url)
        action_html = f' action="{action_attr}"' if action_attr else ""
        page = make_page(
            body=f'<form method="post"{action_html}></form>',
            url=f"https://{target_apex}/page",
        )
        expected = expected_template.format(apex=target_apex, bystander=bystander_url)
        assert page.post_forms[0].resolved_action == expected

    @pytest.mark.parametrize(
        ("input_html", "expected_has_csrf"),
        [
            ('<input type="hidden" name="csrf_token" value="abc">', True),
            ('<input type="hidden" name="authenticity_token" value="abc">', True),
            ('<input type="text" name="csrf_token" value="abc">', False),
            ('<input type="hidden" name="user_id" value="abc">', False),
        ],
    )
    def test_has_csrf_input(self, make_page, input_html, expected_has_csrf) -> None:
        page = make_page(body=f'<form method="post" action="/x">{input_html}</form>')
        assert page.post_forms[0].has_csrf_input is expected_has_csrf

    def test_forms_cached(self, make_page) -> None:
        page = make_page(body='<form method="post" action="/x"></form>')
        first = page.forms
        second = page.forms
        assert first is second


class TestWebpageScripts:
    """<script src="..."> parsing on the Webpage shape."""

    def test_picks_up_scripts_with_src(self, make_page) -> None:
        page = make_page(
            body='<script src="/app.js"></script><script>inline()</script>',
        )
        assert len(page.scripts) == 1
        assert page.scripts[0].url == "/app.js"

    def test_resolved_url(self, make_page, target_apex) -> None:
        page = make_page(
            body='<script src="/app.js"></script>',
            url=f"https://{target_apex}/page",
        )
        assert page.scripts[0].resolved_url == f"https://{target_apex}/app.js"

    def test_absolute_url_unchanged(self, make_page, bystander_url) -> None:
        page = make_page(body=f'<script src="{bystander_url}/lib.js"></script>')
        assert page.scripts[0].resolved_url == f"{bystander_url}/lib.js"

    @pytest.mark.parametrize(
        ("integrity_attr", "expected"),
        [
            (' integrity="sha384-abc"', True),
            ("", False),
            (' integrity=""', False),
        ],
    )
    def test_has_integrity(self, make_page, integrity_attr, expected) -> None:
        page = make_page(body=f'<script src="/a.js"{integrity_attr}></script>')
        assert page.scripts[0].has_integrity is expected

    def test_cached(self, make_page) -> None:
        page = make_page(body='<script src="/a.js"></script>')
        assert page.scripts is page.scripts


class TestWebpageJavascripts:
    """``.js`` / ``.mjs`` filtered subset of ``page.scripts``."""

    def test_includes_js_extension(self, make_page) -> None:
        page = make_page(body='<script src="/app.js"></script>')
        assert len(page.javascripts) == 1

    def test_includes_mjs_extension(self, make_page) -> None:
        # ES modules - browsers serve these natively in production.
        page = make_page(body='<script src="/module.mjs"></script>')
        assert len(page.javascripts) == 1

    def test_includes_js_with_query_string(self, make_page) -> None:
        page = make_page(body='<script src="/app.js?v=2"></script>')
        assert len(page.javascripts) == 1

    def test_excludes_source_formats(self, make_page) -> None:
        # .jsx / .ts / .tsx get transpiled at build time - production
        # targets do not serve them, so they stay out of the filter.
        page = make_page(
            body=(
                '<script src="/app.jsx"></script>'
                '<script src="/app.ts"></script>'
                '<script src="/app.tsx"></script>'
            ),
        )
        assert page.javascripts == []

    def test_excludes_non_js(self, make_page) -> None:
        page = make_page(
            body=(
                '<script src="/app.js"></script>'
                '<script src="/widget.cgi"></script>'
                '<script src="/api/v1/widget"></script>'
            ),
        )
        assert len(page.javascripts) == 1
        assert page.javascripts[0].url == "/app.js"

    def test_scripts_still_includes_all(self, make_page) -> None:
        # The unfiltered set stays available for SRI's broader coverage.
        page = make_page(
            body='<script src="/app.js"></script><script src="/widget.cgi"></script>',
        )
        assert len(page.scripts) == 2


class TestWebpageStylesheets:
    """<link rel="stylesheet" href="..."> parsing on the Webpage shape."""

    def test_picks_up_stylesheets(self, make_page) -> None:
        page = make_page(body='<link rel="stylesheet" href="/style.css">')
        assert len(page.stylesheets) == 1
        assert page.stylesheets[0].url == "/style.css"

    def test_ignores_non_stylesheet_links(self, make_page) -> None:
        page = make_page(
            body=('<link rel="icon" href="/favicon.ico"><link rel="canonical" href="/canonical">'),
        )
        assert page.stylesheets == []

    def test_resolved_url(self, make_page, target_apex) -> None:
        page = make_page(
            body='<link rel="stylesheet" href="/style.css">',
            url=f"https://{target_apex}/page",
        )
        assert page.stylesheets[0].resolved_url == f"https://{target_apex}/style.css"

    @pytest.mark.parametrize(
        ("integrity_attr", "expected"),
        [
            (' integrity="sha384-abc"', True),
            ("", False),
        ],
    )
    def test_has_integrity(self, make_page, integrity_attr, expected) -> None:
        page = make_page(
            body=f'<link rel="stylesheet" href="/style.css"{integrity_attr}>',
        )
        assert page.stylesheets[0].has_integrity is expected

    def test_skips_link_without_href(self, make_page) -> None:
        page = make_page(body='<link rel="stylesheet">')
        assert page.stylesheets == []
