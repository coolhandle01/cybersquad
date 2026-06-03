"""tests/models/test_primitives.py - unit tests for models/primitives/."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from models import (
    FQDN,
    Cidr,
    Email,
    HttpUrl,
    IpAddr,
    IPType,
    Severity,
)

pytestmark = pytest.mark.unit


class TestSeverityEnum:
    def test_all_values_present(self):
        levels = {s.value for s in Severity}
        assert levels == {"informational", "low", "medium", "high", "critical"}

    def test_severity_is_string_enum(self):
        assert isinstance(Severity.HIGH, str)
        assert Severity.HIGH == "high"


class _FQDNProbe(BaseModel):
    """Thin probe model used to drive the FQDN validator in isolation."""

    value: FQDN


class TestFQDN:
    def test_accepts_target_apex(self, target_url):
        # urlparse hostname is the canonical way to derive a FQDN-shaped
        # string from a URL fixture; using the fixture keeps test intent
        # ("the in-scope target") readable at the call site.
        from urllib.parse import urlparse

        host = urlparse(target_url).hostname or ""
        apex = host.split(".", 1)[-1]  # "example.com" from "victim.example.com"
        assert _FQDNProbe(value=apex).value == apex

    def test_accepts_victim_subdomain(self, target_url):
        from urllib.parse import urlparse

        host = urlparse(target_url).hostname or ""
        assert _FQDNProbe(value=host).value == host

    def test_accepts_single_label(self):
        # ``localhost`` is the canonical single-label hostname; no URL fixture
        # exposes one because the rest of the codebase doesn't reach for it.
        assert _FQDNProbe(value="localhost").value == "localhost"

    def test_accepts_numeric_labels(self):
        # 10.0.0.1 looks IP-shaped but parses as a valid hostname per RFC 1123
        # label rules (digits are allowed). The scope filter is the next layer
        # that decides whether to accept it as an in-scope target.
        assert _FQDNProbe(value="10.0.0.1").value == "10.0.0.1"

    def test_lowercases_victim_host(self, target_url):
        from urllib.parse import urlparse

        host = urlparse(target_url).hostname or ""
        assert _FQDNProbe(value=host.upper()).value == host

    def test_strips_whitespace_around_victim_host(self, target_url):
        from urllib.parse import urlparse

        host = urlparse(target_url).hostname or ""
        assert _FQDNProbe(value=f"  {host}  ").value == host

    def test_rejects_malformed(self, target_url):
        """Walks the malformed corpus, deriving each case from target_url
        so test intent ("a deliberately broken version of the in-scope
        target") is readable. Pytest parametrize literals cannot consume
        fixtures, so a single dedicated method loops the corpus instead.
        """
        from urllib.parse import urlparse

        host = urlparse(target_url).hostname or ""
        cases: list[tuple[str, str]] = [
            ("", "empty"),
            ("   ", "whitespace only"),
            (f"https://{host}", "scheme present"),
            (f"ftp://{host}", "non-http scheme"),
            (f"{host}:8080", "port present"),
            (f"{host}/path", "path present"),
            (f"{host}/", "trailing slash"),
            (f"-{host}", "leading hyphen"),
            (f"{host}-", "trailing hyphen on label"),
            (host.replace(".", "..", 1), "empty label"),
            ("a" * 64 + f".{host}", "label > 63 chars"),
            (".".join(["a"] * 200), "total > 253 chars"),
            (host.replace(".", " .", 1), "space in label"),
            (f"{host}\nextra", "newline injection"),
        ]
        for value, label in cases:
            with pytest.raises(ValidationError, match=r".*"):
                _FQDNProbe.model_validate({"value": value})
            # ``label`` is unused at the assertion level but appears in the
            # case tuple so a future debugger can identify which case failed.
            del label

    def test_rejects_non_string(self):
        with pytest.raises(ValidationError):
            _FQDNProbe.model_validate({"value": 42})


class _HttpUrlProbe(BaseModel):
    """Thin probe model used to drive the HttpUrl validator in isolation."""

    value: HttpUrl


class TestHttpUrl:
    def test_accepts_target_url(self, target_url):
        assert _HttpUrlProbe(value=target_url).value == target_url

    def test_accepts_target_url_with_path(self, target_url):
        url = f"{target_url}/api/users?id=1"
        assert _HttpUrlProbe(value=url).value == url

    def test_accepts_http_scheme(self, target_url):
        url = target_url.replace("https://", "http://")
        assert _HttpUrlProbe(value=url).value == url

    def test_rejects_malformed(self, target_url):
        """Walks the malformed corpus, deriving each case from target_url so
        intent ("a deliberately broken URL based on the in-scope target") is
        readable at the call site. Delegates to ``pydantic.HttpUrl`` for the
        URL contract; the host component then runs through the
        ``FQDN`` validator so RFC 1123 strictness holds inside URLs
        too - ``-evil.example.com`` rejects bare, and
        ``https://-evil.example.com`` rejects wrapped (the leading-hyphen
        case below pins that defense-in-depth).
        """
        from urllib.parse import urlparse

        host = urlparse(target_url).hostname or ""
        cases: list[tuple[str, str]] = [
            ("", "empty"),
            ("   ", "whitespace only"),
            (host, "no scheme - bare hostname"),
            (f"ftp://{host}", "non-http scheme"),
            ("javascript:alert(1)", "javascript scheme"),
            ("file:///etc/passwd", "file scheme"),
            ("https://", "scheme with no host"),
            ("https:///path", "scheme + path with no host"),
            (f"https://-{host}", "hostname inside URL fails RFC 1123"),
        ]
        for value, label in cases:
            with pytest.raises(ValidationError):
                _HttpUrlProbe.model_validate({"value": value})
            del label

    def test_preserves_path_and_query(self, target_url):
        url = f"{target_url}/search?q=hello&page=2#top"
        assert _HttpUrlProbe(value=url).value == url


class _IpAddrProbe(BaseModel):
    """Thin probe model used to drive the IpAddr validator in isolation."""

    value: IpAddr


class TestIpAddr:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            # IPv4 dotted-quad
            ("8.8.8.8", "8.8.8.8"),
            ("1.1.1.1", "1.1.1.1"),
            ("192.168.0.1", "192.168.0.1"),
            ("0.0.0.0", "0.0.0.0"),
            ("255.255.255.255", "255.255.255.255"),
            # IPv6 - canonical form returns the compressed shape
            ("::1", "::1"),
            ("0:0:0:0:0:0:0:1", "::1"),
            ("2001:db8::1", "2001:db8::1"),
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
            # Whitespace tolerated and stripped
            ("  8.8.8.8  ", "8.8.8.8"),
        ],
    )
    def test_valid_address_canonicalises(self, raw, expected):
        assert _IpAddrProbe(value=raw).value == expected

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "   ",
            "example.com",
            "not-an-ip",
            "1.2.3.4.5",
            "256.0.0.1",
            "1.2.3",
            "999.999.999.999",
        ],
    )
    def test_rejects_malformed(self, bad):
        with pytest.raises(ValidationError):
            _IpAddrProbe(value=bad)

    def test_rejects_cidr_notation(self):
        # CIDR is a netblock, not an IP; explicit reject so the error
        # message names the cause.
        with pytest.raises(ValidationError, match="CIDR"):
            _IpAddrProbe(value="1.2.3.0/24")

    def test_rejects_ipv6_zone_identifier(self):
        # Link-local zone IDs (``fe80::1%eth0``) shouldn't appear in
        # recon JSON - they're scoped to the scanner's host, not stable.
        with pytest.raises(ValidationError, match="zone identifier"):
            _IpAddrProbe(value="fe80::1%eth0")

    def test_rejects_non_string_input(self):
        with pytest.raises(ValidationError):
            _IpAddrProbe.model_validate({"value": ["1.2.3.4"]})

    def test_serialisation_roundtrip(self):
        original = _IpAddrProbe(value="2001:db8::1")
        restored = _IpAddrProbe.model_validate_json(original.model_dump_json())
        assert restored.value == "2001:db8::1"

    def test_runtime_type_is_str(self):
        # IpAddr is Annotated[str, ...] - consumers that do
        # f"https://{ip}" / ip.startswith(...) / dict-key keep working.
        probe = _IpAddrProbe(value="8.8.8.8")
        assert isinstance(probe.value, str)
        assert probe.value.startswith("8.")


class _EmailProbe(BaseModel):
    """Thin probe model used to drive the Email validator in isolation."""

    value: Email


class TestEmail:
    @pytest.mark.parametrize(
        "raw",
        [
            "abuse@example.com",
            "first.last@sub.example.com",
            "a@b.co",
        ],
    )
    def test_accepts_canonical_shapes(self, raw):
        assert _EmailProbe(value=raw).value == raw

    def test_normalises_to_lowercase(self):
        # email_validator returns the normalised form (both local-part
        # and domain case-folded) so equality holds across input
        # variants.
        assert _EmailProbe(value="Abuse@Example.COM").value == "abuse@example.com"

    @pytest.mark.parametrize(
        "bad",
        ["", "   ", "no-at-sign", "@no-local-part.com", "missing-domain@", "two@@example.com"],
    )
    def test_rejects_malformed(self, bad):
        with pytest.raises(ValidationError):
            _EmailProbe(value=bad)

    def test_runtime_type_is_str(self):
        # Email is Annotated[str, ...] so f"mailto:{email}" /
        # email.split("@") keep working without an audit.
        probe = _EmailProbe(value="abuse@example.com")
        assert isinstance(probe.value, str)
        assert "@" in probe.value


class TestIPType:
    def test_values(self):
        assert {t.value for t in IPType} == {"IPv4", "IPv6"}

    def test_is_string_enum(self):
        assert isinstance(IPType.IPV4, str)
        assert IPType.IPV4 == "IPv4"


class _CidrProbe(BaseModel):
    """Thin probe model used to drive the Cidr validator in isolation."""

    value: Cidr


class TestCidr:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("8.8.8.0/24", "8.8.8.0/24"),
            ("8.8.8.8/24", "8.8.8.0/24"),  # host bits normalise to the network
            (" 10.0.0.0/8 ", "10.0.0.0/8"),  # whitespace stripped
            ("2001:db8::/32", "2001:db8::/32"),
        ],
    )
    def test_valid_cidr_normalises(self, raw, expected):
        assert _CidrProbe(value=raw).value == expected

    def test_rejects_non_cidr(self, target_url):
        """The bare cases stay literal; the hostname-shaped case derives its
        host from target_url so "a domain where a CIDR was expected" reads at
        the call site. Parametrize can't consume fixtures, so a single method
        loops the corpus (mirrors TestFQDN / TestHttpUrl).
        """
        from urllib.parse import urlparse

        host = urlparse(target_url).hostname or ""
        cases: list[str] = ["", "   ", "8.8.8.8", "not-a-cidr", "999.0.0.0/8", f"{host}/24"]
        for bad in cases:
            with pytest.raises(ValidationError):
                _CidrProbe(value=bad)

    def test_runtime_type_is_str(self):
        # Cidr is Annotated[str, ...] so consumers keep treating it as a string.
        probe = _CidrProbe(value="8.8.8.0/24")
        assert isinstance(probe.value, str)

    def test_serialisation_roundtrip(self):
        original = _CidrProbe(value="2001:db8::/32")
        restored = _CidrProbe.model_validate_json(original.model_dump_json())
        assert restored.value == "2001:db8::/32"
