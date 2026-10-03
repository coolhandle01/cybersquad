"""HTML fetch-and-parse helper.

Wraps ``http.get`` and returns a ``Webpage`` that bundles the response,
parsed soup, framework-detection result, and form / script / stylesheet
/ cookie recipes probes used to inline. Probes get a typed page object
and ask it questions; the soup mechanics stay here.

The framework-detection signals live next to the soup recipes (rather
than in ``tools/http.py`` or a separate ``tools/framework.py``)
because they operate on the (response, soup) pair this module owns.
The pure transport layer in ``tools/http.py`` stays free of model
knowledge.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from models.framework import Framework
from tools import http

# Name fragments that suggest a CSRF protection token. Lifted from
# tools/pentest/csrf.py at the framework-aware-PT refactor so the soup
# recipes live one layer up from probe code; the probe consumes Webpage.
_CSRF_NAME_FRAGMENTS = (
    "csrf",
    "token",
    "_token",
    "authenticity_token",
    "nonce",
    "xsrf",
)

# High-confidence framework signals from response cookies. Cookie-name
# match is exact, case-insensitive. Ambiguous signals (XSRF-TOKEN
# cookie matches both Angular and Laravel) are deliberately NOT mapped
# here - they still drive the generic page_protected boolean via the
# fragment-based check above, but the typed channel stays clean.
_FRAMEWORK_COOKIE_SIGNALS: tuple[tuple[Framework, str], ...] = (
    (Framework.django, "csrftoken"),
    (Framework.tornado, "_xsrf"),
)

# High-confidence framework signals from <meta> tags. Rails ships
# `<meta name="csrf-param">` alongside `csrf-token`, distinguishing it
# from Spring (csrf-token only) - so csrf-param is the Rails-specific
# tell. Plain `csrf-token` meta stays unmapped (Rails or Spring; cannot
# tell apart here).
_FRAMEWORK_META_SIGNALS: tuple[tuple[Framework, str], ...] = ((Framework.rails, "csrf-param"),)

# URL-substring -> Framework. Matched case-insensitively against the
# raw href / src AND the resolved absolute URL of every <script> and
# <link rel="stylesheet"> on the page. Order matters: ``@angular/``
# (modern's scoped npm package) is checked before ``angular.js`` so a
# build that bundles both does not get classified as AngularJS.
#
# Bootstrap is detected here even though it is a CSS framework: per-
# version XSS / CVE bookkeeping has the same shape as a JS framework's,
# and SRI on the link does NOT make the underlying version safe.
_FRAMEWORK_URL_SIGNALS: tuple[tuple[str, Framework], ...] = (
    # Modern Angular - scoped npm package or zone.js runtime
    ("@angular/", Framework.angular),
    ("zone.js", Framework.angular),
    # Legacy AngularJS - unscoped angular.js / angular.min.js
    ("angular.js", Framework.angularjs),
    ("angular.min.js", Framework.angularjs),
    # React
    ("/react.", Framework.react),
    ("react-dom", Framework.react),
    ("react.production", Framework.react),
    ("react.development", Framework.react),
    # Vue
    ("/vue.", Framework.vue),
    ("vue.min.js", Framework.vue),
    ("vuejs", Framework.vue),
    # Next.js - the underscore-prefixed static dir is unique to Next
    ("/_next/", Framework.nextjs),
    ("next/dist", Framework.nextjs),
    # Bootstrap (CSS + JS bundles)
    ("bootstrap.", Framework.bootstrap),
)

# Extensions that mark a URL as a JavaScript bundle worth probing for
# source maps / framework signatures. ``.mjs`` is the ES-modules
# extension served natively to modern browsers. Source-format
# extensions (.jsx / .ts / .tsx / .coffee) are deliberately excluded -
# those get transpiled to .js / .mjs at build time and don't appear on
# a production target.
_JS_EXTENSIONS = (".js", ".mjs")


@dataclass(frozen=True)
class Form:
    """One <form> element observed on a page.

    ``resolved_action`` is the form's action URL computed at parse time
    against the page URL so probes do not have to ``urljoin`` at every
    call site. ``has_csrf_input`` is True when the form contains a
    hidden input whose name matches any CSRF-pattern fragment.

    Only ``get`` and ``post`` ever appear in ``method``: per the HTML
    spec a form's ``method`` attribute accepts only those two values.
    Server-side overrides for PUT / PATCH / DELETE (Rails ``_method``
    hidden field, Laravel ``@method`` directive) are POST-encoded at
    the wire level - probes that care about override semantics inspect
    the form's hidden inputs themselves.
    """

    action: str  # raw action attribute, may be empty
    resolved_action: str  # action resolved relative to the page URL
    method: str  # "get" / "post" (lower-cased)
    has_csrf_input: bool


@dataclass(frozen=True)
class SubResource:
    """One linked sub-resource observed on a page (script src, stylesheet href).

    Unified shape because ``<script src>`` and ``<link href>`` are
    structurally identical from the SRI / cross-origin / integrity
    point of view - the only difference is the HTML attribute name.
    Which collection the SubResource came from (``scripts`` /
    ``javascripts`` / ``stylesheets``) is the kind discriminator;
    SRI's "missing integrity" string formats from there.

    ``resolved_url`` is the absolute URL computed at parse time against
    the page URL. ``has_integrity`` is True when the tag carries a
    non-empty ``integrity`` attribute (a Subresource Integrity hash).
    """

    url: str  # raw src or href attribute
    resolved_url: str  # url resolved relative to the page URL
    has_integrity: bool


class Webpage:
    """One fetched HTML page wrapping response, soup, and derived recipes.

    Constructed via ``tools.html.fetch(url, ...)``; tests can build one
    directly from a ``requests.Response`` mock via ``Webpage(response)``.
    The underlying ``response`` is exposed for probes that need raw
    access; the soup is parsed lazily and derived page properties are
    ``cached_property`` so a probe asking for ``post_forms`` and
    ``frameworks`` only pays the parse cost once.

    Not a frozen dataclass: ``cached_property`` writes to the instance.
    Consumers should treat the instance as immutable - tests construct
    a fresh Webpage per case rather than mutating a shared one.
    """

    def __init__(self, response: requests.Response) -> None:
        self.response = response

    @cached_property
    def mimetype(self) -> str:
        """The response's MIME type, lower-cased and stripped of parameters.

        ``Content-Type: text/html; charset=utf-8`` returns ``"text/html"``;
        ``Content-Type: application/json`` returns ``"application/json"``.
        Empty string when the header is absent. Use this rather than
        re-parsing the Content-Type at every call site - probes can
        ``match`` / ``case`` on the return value cleanly.
        """
        raw = self.response.headers.get("Content-Type", "")
        return raw.split(";", 1)[0].strip().lower()

    @cached_property
    def soup(self) -> BeautifulSoup:
        """Parsed soup for the response body.

        Returns an empty soup when the Content-Type is not text/html -
        callers can treat an empty soup as a skip condition rather than
        checking the header themselves. For probes that DO want to
        branch on the MIME type, ``mimetype`` exposes the parsed value.
        """
        body = self.response.text if self.mimetype == "text/html" else ""
        return BeautifulSoup(body, "html.parser")

    @property
    def url(self) -> str:
        """The page URL (post-redirect, from the underlying response)."""
        return self.response.url

    @cached_property
    def frameworks(self) -> set[Framework]:
        """Frameworks detected from cookies, meta tags, and script / link URLs.

        Three signal sources, all high-confidence (one false positive
        per million pages is the bar):

        * **Response cookies** - ``csrftoken`` (Django), ``_xsrf``
          (Tornado). See ``_FRAMEWORK_COOKIE_SIGNALS``.
        * **HTML <meta> tags** - ``csrf-param`` (Rails-specific tell;
          distinguishes from Spring which only ships ``csrf-token``).
          See ``_FRAMEWORK_META_SIGNALS``.
        * **<script> src and <link> href URL substrings** - identifies
          client-side stacks (React, Vue, AngularJS / Angular, Next.js)
          and Bootstrap. See ``_FRAMEWORK_URL_SIGNALS``.

        Ambiguous CSRF-pattern signals (``XSRF-TOKEN`` cookie matches
        both Angular HttpClient and Laravel; plain ``csrf-token`` meta
        matches Rails or Spring) drive ``page_protected`` but stay out
        of this typed set.
        """
        detected: set[Framework] = set()

        # SIM118 wants `for name in self.response.cookies`, but cookies is a
        # RequestsCookieJar, not a dict: iterating it yields Cookie objects,
        # while .keys() yields the name strings we match on. The .keys() call
        # is load-bearing here, so the rule is suppressed on that line.
        cookie_names = {name.lower() for name in self.response.cookies.keys()}  # noqa: SIM118
        for fw, signal in _FRAMEWORK_COOKIE_SIGNALS:
            if signal in cookie_names:
                detected.add(fw)

        meta_names = {(m.get("name") or "").lower() for m in self.soup.find_all("meta")}
        for fw, signal in _FRAMEWORK_META_SIGNALS:
            if signal in meta_names:
                detected.add(fw)

        # URL-pattern detection across scripts + stylesheets. Match both
        # the raw href / src (relative URLs like ``/static/react.js``)
        # and the resolved absolute URL (CDN refs that hit a known npm
        # path even when the relative form doesn't).
        urls: list[str] = []
        for r in self.scripts:
            urls.append(r.url.lower())
            urls.append(r.resolved_url.lower())
        for r in self.stylesheets:
            urls.append(r.url.lower())
            urls.append(r.resolved_url.lower())
        for signal, fw in _FRAMEWORK_URL_SIGNALS:
            if any(signal in url for url in urls):
                detected.add(fw)

        return detected

    def has_csrf_cookie(self) -> bool:
        """True if the response sets a cookie with a CSRF-pattern name.

        The double-submit cookie pattern (Angular's XSRF-TOKEN,
        Django's csrftoken, Tornado's _xsrf) protects POSTs without
        hidden form inputs - JS reads the cookie and sends its value
        back as a custom request header.
        """
        # .keys() is load-bearing: iterating a RequestsCookieJar yields
        # Cookie objects, while .keys() yields the name strings we match on.
        for name in self.response.cookies.keys():  # noqa: SIM118
            if any(frag in name.lower() for frag in _CSRF_NAME_FRAGMENTS):
                return True
        return False

    def has_csrf_meta_tag(self) -> bool:
        """True if the page contains a <meta> tag carrying a CSRF token.

        Rails, Spring, and other frameworks place the CSRF token in a
        ``<meta name="csrf-token" content="...">`` element; the
        framework's JS reads it from the DOM and sends it as a request
        header. Forms on such pages are protected even without hidden
        inputs.
        """
        for meta in self.soup.find_all("meta"):
            name = (meta.get("name") or "").lower()
            if any(frag in name for frag in _CSRF_NAME_FRAGMENTS):
                return True
        return False

    @cached_property
    def page_protected(self) -> bool:
        """True if a CSRF-pattern cookie OR meta tag is present.

        Use this to suppress the "missing CSRF token in form" finding
        on pages where the framework provides JS-side CSRF protection
        without a hidden input. Per-view bypasses (Django ``@csrf_exempt``,
        Rails ``skip_before_action``, Spring ``csrf().disable()``,
        Laravel ``$except``) mean this signal cannot be trusted to
        cover every route - the Origin-validation probe must still
        fire even on protected pages.
        """
        return self.has_csrf_cookie() or self.has_csrf_meta_tag()

    @cached_property
    def forms(self) -> list[Form]:
        """All <form> elements on the page (any method)."""
        out: list[Form] = []
        for form_el in self.soup.find_all("form"):
            method = (form_el.get("method") or "get").lower()
            action = form_el.get("action") or ""
            resolved = urljoin(self.url, action) if action else self.url
            has_csrf = any(
                (inp.get("type") or "").lower() == "hidden"
                and any(frag in (inp.get("name") or "").lower() for frag in _CSRF_NAME_FRAGMENTS)
                for inp in form_el.find_all("input")
            )
            out.append(
                Form(
                    action=action,
                    resolved_action=resolved,
                    method=method,
                    has_csrf_input=has_csrf,
                )
            )
        return out

    @cached_property
    def post_forms(self) -> list[Form]:
        """All <form method="post"> elements on the page."""
        return [f for f in self.forms if f.method == "post"]

    @cached_property
    def get_forms(self) -> list[Form]:
        """All <form method="get"> elements on the page."""
        return [f for f in self.forms if f.method == "get"]

    @cached_property
    def scripts(self) -> list[SubResource]:
        """All <script src="..."> elements on the page (any URL shape).

        Use this for SRI / cross-origin / integrity checks that apply to
        every script tag regardless of file extension. Use
        ``javascripts`` for ``.js``-specific work (source map probes,
        bundle analysis) so the extension filter lives at the boundary
        rather than at every call site.
        """
        out: list[SubResource] = []
        for tag in self.soup.find_all("script", src=True):
            src = str(tag["src"])
            resolved = urljoin(self.url, src) if src else self.url
            has_integrity = bool(tag.get("integrity"))
            out.append(SubResource(url=src, resolved_url=resolved, has_integrity=has_integrity))
        return out

    @cached_property
    def javascripts(self) -> list[SubResource]:
        """Subset of ``scripts`` whose URL path ends in a JS extension.

        Matches ``.js`` (classic) and ``.mjs`` (ES modules - browsers
        serve these natively in production). Strips the query string
        before the suffix check so ``app.js?v=2`` counts.

        Deliberately does NOT match ``.jsx`` / ``.ts`` / ``.tsx`` /
        ``.coffee`` - those are source formats that get transpiled to
        ``.js`` at build time; a production target won't serve them.
        A dev-mode scan that wanted them would be a separate carve-out.

        Use this when the probe's logic only makes sense for actual
        JavaScript bundles (e.g. fetching for a ``sourceMappingURL``
        comment). Use ``scripts`` for any-script SRI / integrity work.
        """
        return [s for s in self.scripts if s.url.split("?", 1)[0].endswith(_JS_EXTENSIONS)]

    @cached_property
    def stylesheets(self) -> list[SubResource]:
        """All <link rel="stylesheet" href="..."> elements on the page."""
        out: list[SubResource] = []
        for tag in self.soup.find_all("link"):
            rel = " ".join(tag.get("rel") or []).lower()
            if "stylesheet" not in rel:
                continue
            href = str(tag.get("href") or "")
            if not href:
                continue
            resolved = urljoin(self.url, href)
            has_integrity = bool(tag.get("integrity"))
            out.append(SubResource(url=href, resolved_url=resolved, has_integrity=has_integrity))
        return out

    @cached_property
    def favicon(self) -> str:
        """The page's favicon URL, resolved absolute.

        Walks ``<link rel="icon">`` and ``<link rel="shortcut icon">``
        tags first. Falls back to the implicit ``/favicon.ico`` at the
        page origin when no explicit link is declared - the same fallback
        the browser performs.

        Useful for asset fingerprinting: MurmurHash3 of the favicon
        bytes is the canonical input to Shodan / Censys "favicon-hash"
        searches, which find every host serving the same icon. Future
        OSINT-side recon can fetch and hash this URL to pivot from one
        in-scope asset to its sibling deployments.
        """
        for link in self.soup.find_all("link", rel=True):
            rels = [str(r).lower() for r in (link.get("rel") or [])]
            if "icon" in rels:
                href = str(link.get("href") or "")
                if href:
                    return urljoin(self.url, href)
        parsed = urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}/favicon.ico"


def fetch(url: str, **kwargs: object) -> Webpage:
    """GET url and return a Webpage wrapping the response.

    Use this instead of calling ``http.get`` + ``BeautifulSoup`` separately.
    Pass any ``http.get`` kwargs (timeout, allow_redirects, headers, etc.)
    through.

    The returned ``Webpage`` exposes ``response``, lazily-parsed ``soup``,
    and cached_property accessors for derived page properties
    (``frameworks``, ``page_protected``, ``forms`` / ``post_forms`` /
    ``get_forms``, ``scripts``, ``stylesheets``). When the Content-Type
    is not text/html the soup is empty and the derived properties return
    their natural empty values.
    """
    # The ``**kwargs: object`` signature on ``fetch`` is deliberately loose so
    # callers forward any ``http.get`` keyword (timeout / allow_redirects /
    # headers / ...) without us mirroring the signature here. Mypy can't
    # reconcile ``object``-typed values against http.get's typed parameters;
    # the runtime contract is fine - http.get itself raises on bad kwargs.
    return Webpage(http.get(url, **kwargs))  # type: ignore[arg-type]
