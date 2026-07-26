"""tests/tools/recon/test_scope.py - unit tests for tools/recon/scope.py.

The scope guard is security-critical: ``filter_in_scope`` (and the
``TargetFQDN`` / ``TargetEndpoint`` typed aliases that wrap it at the
args_schema boundary) decide which hosts we are authorised to touch. An
out-of-scope false positive would have us testing targets we have no
permission for, so the boundary / suffix-spoofing cases are pinned here.
``host_of`` is the thin URL-host extractor the guard reads.
"""

from __future__ import annotations

import pytest

from models.h1 import Programme
from tools.recon.scope import filter_in_scope, host_of

pytestmark = pytest.mark.unit


# host_of - thin stdlib urlparse wrapper. Returns the URL's hostname
# or "" when the input has no host (a bare hostname rather than a URL).
class TestHostOf:
    def test_url_with_scheme(self, target_apex):
        assert host_of(f"https://{target_apex}") == "example.com"

    def test_url_with_path(self, target_apex):
        assert host_of(f"https://api.{target_apex}/v1/search") == "api.example.com"

    def test_url_with_port(self, target_apex):
        assert host_of(f"https://{target_apex}:8443") == "example.com"

    def test_bare_hostname_returns_empty(self):
        """No scheme means urlparse cannot identify a netloc; the helper
        is intentionally URL-only and returns "" rather than guessing."""
        assert host_of("example.com") == ""


# filter_in_scope
class TestFilterInScope:
    """
    The scope guard is security-critical - an out-of-scope false positive
    would cause us to test targets we're not authorised to touch.
    """

    def test_exact_domain_match(self, programme):
        assert filter_in_scope(["example.com"], programme) == ["example.com"]

    def test_genuine_subdomain_passes(self, programme):
        result = filter_in_scope(["api.example.com"], programme)
        assert "api.example.com" in result

    def test_deep_subdomain_passes(self, programme):
        result = filter_in_scope(["deep.api.example.com"], programme)
        assert "deep.api.example.com" in result

    def test_out_of_scope_domain_blocked(self, programme):
        result = filter_in_scope(["other.com"], programme)
        assert result == []

    def test_boundary_spoofing_blocked(self, programme):
        """evil.notexample.com must NOT pass as in-scope for example.com."""
        result = filter_in_scope(["evil.notexample.com"], programme)
        assert result == [], "Scope guard boundary bug: evil.notexample.com matched example.com"

    def test_suffix_spoofing_blocked(self, programme):
        """attackerexample.com must NOT match *.example.com."""
        result = filter_in_scope(["attackerexample.com"], programme)
        assert result == []

    def test_mixed_batch(self, programme):
        hosts = ["api.example.com", "evil.notexample.com", "admin.example.com", "other.io"]
        result = filter_in_scope(hosts, programme)
        assert "api.example.com" in result
        assert "admin.example.com" in result
        assert "evil.notexample.com" not in result
        assert "other.io" not in result

    def test_empty_input(self, programme):
        assert filter_in_scope([], programme) == []

    def test_no_scope_items(self):
        bare_programme = Programme(
            handle="bare",
            name="Bare",
            url="https://hackerone.com/bare",
            bounty_table={},
            in_scope=[],
            out_of_scope=[],
        )
        assert filter_in_scope(["example.com"], bare_programme) == []

    def test_non_url_wildcard_scope_items_are_skipped(self, target_apex):
        """``filter_in_scope`` only consults URL / WILDCARD scope items.
        A programme whose in-scope catalogue mixes other ``ScopeType``
        members (``IP_ADDRESS``, ``CIDR``, ``OTHER``, mobile-app IDs)
        skips those entries entirely - they do not match hostnames.
        Pins the branch that would otherwise silently treat a CIDR
        ``asset_identifier`` as a hostname pattern."""
        from models.h1 import ScopeItem, ScopeType

        prog = Programme(
            handle="mixed",
            name="Mixed Scope",
            url="https://hackerone.com/mixed",
            bounty_table={},
            in_scope=[
                ScopeItem(asset_identifier="10.0.0.0/8", asset_type=ScopeType.CIDR),
                ScopeItem(asset_identifier="192.0.2.1", asset_type=ScopeType.IP_ADDRESS),
                ScopeItem(asset_identifier="com.example.app", asset_type=ScopeType.OTHER),
                ScopeItem(asset_identifier=f"*.{target_apex}", asset_type=ScopeType.WILDCARD),
            ],
            out_of_scope=[],
        )
        # Only the WILDCARD entry matches; the IP / CIDR / OTHER entries
        # are skipped per the ``continue`` branch.
        assert filter_in_scope([f"api.{target_apex}"], prog) == [f"api.{target_apex}"]
        assert filter_in_scope(["10.0.0.5"], prog) == []
        assert filter_in_scope(["com.example.app"], prog) == []


class TestInScopeTypedAliases:
    """The ``TargetFQDNs`` / ``TargetEndpoints`` typed aliases run
    a Pydantic ``AfterValidator`` at ``args_schema.model_validate(...)``
    time - that is the scope guard. List variants filter silently
    (mixed candidate lists pass survivors); single variants
    (``TargetFQDN`` / ``TargetEndpoint``) raise ``ValueError`` on
    an OOS pick. The aliases are exercised end-to-end via a small
    args_schema stub that mirrors what the cloud / probe / OSINT
    wrappers declare in production.
    """

    def test_list_hostnames_filters_oos(self, programme_in_workspace, target_apex):
        from pydantic import BaseModel

        from tools.recon.scope import TargetFQDNs

        class _Args(BaseModel):
            hostnames: TargetFQDNs

        parsed = _Args.model_validate(
            {"hostnames": [f"api.{target_apex}", "bystander.example.org"]}
        )
        assert parsed.hostnames == [f"api.{target_apex}"]

    def test_list_endpoints_filters_oos(self, programme_in_workspace, target_apex, bystander_url):
        from pydantic import BaseModel

        from tools.recon.scope import TargetEndpoints

        class _Args(BaseModel):
            endpoints: TargetEndpoints

        parsed = _Args.model_validate(
            {
                "endpoints": [
                    {"url": f"https://api.{target_apex}", "status_code": 200},
                    {"url": bystander_url, "status_code": 200},
                ]
            }
        )
        assert len(parsed.endpoints) == 1
        assert parsed.endpoints[0].url == f"https://api.{target_apex}"

    def test_single_hostname_rejects_oos(self, programme_in_workspace):
        from pydantic import BaseModel, ValidationError

        from tools.recon.scope import TargetFQDN

        class _Args(BaseModel):
            hostname: TargetFQDN

        with pytest.raises(ValidationError, match="not in the selected programme's scope"):
            _Args.model_validate({"hostname": "bystander.example.org"})

    def test_single_endpoint_rejects_oos(self, programme_in_workspace, bystander_url):
        from pydantic import BaseModel, ValidationError

        from tools.recon.scope import TargetEndpoint

        class _Args(BaseModel):
            endpoint: TargetEndpoint

        with pytest.raises(ValidationError, match="not in the selected programme's scope"):
            _Args.model_validate({"endpoint": {"url": bystander_url, "status_code": 200}})

    def test_empty_list_skips_programme_lookup(self):
        """An empty list short-circuits the validator - no
        ``current_programme()`` lookup. No ``programme_in_workspace``
        fixture is taken, so the lookup would raise if it ran."""
        from pydantic import BaseModel

        from tools.recon.scope import TargetFQDNs

        class _Args(BaseModel):
            hostnames: TargetFQDNs

        parsed = _Args.model_validate({"hostnames": []})
        assert parsed.hostnames == []
