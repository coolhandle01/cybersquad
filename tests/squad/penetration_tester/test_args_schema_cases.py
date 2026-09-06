"""tests/squad/penetration_tester/test_args_schema_cases.py - agent-specific
accept / reject cases for the Penetration Tester's ``args_schema``s.

Sibling to ``test_args_schemas.py``, which carries the generic contract
loop (every tool wires an explicit schema, every field has a description,
closed-world mapping) parametrised over ``MEMBER.schemas``. The cases here
are the ones the generic loop cannot express: StrEnum payload reject
tables, the JWT token+endpoint shape, ``FQDN`` vs URL rejection,
required-field rejection per family, and the empty-list / known-good
acceptance shapes.

The behavioural tests (``test_ssrf.py``, ``test_idor.py`` etc.) cover
probe behaviour separately.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from squad.penetration_tester import (
    _AdminPanelsArgs,
    _AzureBlobContainerArgs,
    _AzureSasTokenArgs,
    _CmdInjectionArgs,
    _ConsulVaultPathArgs,
    _ConsulVaultPortArgs,
    _CookieCheckArgs,
    _CouchdbCheckArgs,
    _CpanelArgs,
    _CsrfCheckArgs,
    _DirectadminArgs,
    _ElasticsearchCheckArgs,
    _ErrorDisclosureArgs,
    _GrafanaPathArgs,
    _GrafanaPortArgs,
    _HeaderInjectionArgs,
    _HeaderXssArgs,
    _HostHeaderArgs,
    _HppArgs,
    _IdorArgs,
    _JwtCheckArgs,
    _KibanaPathArgs,
    _KibanaPortArgs,
    _LdapInjectionArgs,
    _MongodbCheckArgs,
    _MysqlCheckArgs,
    _NosqliArgs,
    _NucleiScanArgs,
    _OpenRedirectArgs,
    _PathTraversalArgs,
    _PleskArgs,
    _PortainerPathArgs,
    _PortainerPortArgs,
    _PostgresqlCheckArgs,
    _PromptInjectionArgs,
    _PrototypePollutionArgs,
    _PtReconEndpointsArgs,
    _PtReconOpenPortsArgs,
    _PtReconSubdomainsArgs,
    _RedisCheckArgs,
    _S3CheckArgs,
    _SaveFindingsArgs,
    _SensitiveFilesArgs,
    _SourceMapsArgs,
    _SqlmapArgs,
    _SriCheckArgs,
    _SsrfArgs,
    _SstiArgs,
    _WebminArgs,
    _XssArgs,
    _XxeArgs,
)
from squad.tools.workspace_tools import (
    _ListRunFilesArgs,
    _ReadAttackForestArgs,
    _ReadRunFileArgs,
)

pytestmark = pytest.mark.unit


# Every schema in this file with a typed-target field
# (``TargetFQDNs`` / ``TargetEndpoints`` / ``TargetFQDN`` /
# ``TargetEndpoint``) runs its ``AfterValidator`` during
# ``model_validate`` - and that validator calls ``current_programme()``.
# Autousing ``programme_in_workspace`` stages a programme into the
# rundir so every schema-shape test has the run-time context the
# validator needs. Tests that explicitly want a missing-programme
# branch should re-monkeypatch to undo it.
@pytest.fixture(autouse=True)
def _seed_programme(programme_in_workspace):
    return programme_in_workspace


# Cloud wrappers that take ``hostnames: list[FQDN]`` and scope-filter
# via ``filter_in_scope``. Used by the missing-required-hostnames
# parametrize below. Every cloud wrapper now takes a typed target -
# storage no longer needs an exception now that bucket-name fuzzing
# is gone; the agent picks S3 / Azure hostnames OSINT actually
# discovered in recon.subdomains.
_HOSTNAMES_CLOUD_SCHEMAS: list[type[BaseModel]] = [
    _S3CheckArgs,
    _AzureBlobContainerArgs,
    _ElasticsearchCheckArgs,
    _CouchdbCheckArgs,
    _RedisCheckArgs,
    _MongodbCheckArgs,
    _PostgresqlCheckArgs,
    _MysqlCheckArgs,
    _CpanelArgs,
    _PleskArgs,
    _DirectadminArgs,
    _WebminArgs,
    _GrafanaPortArgs,
    _KibanaPortArgs,
    _PortainerPortArgs,
    _ConsulVaultPortArgs,
]

# Cloud wrappers that take ``endpoints: list[Endpoint]`` and scope-filter
# via ``filter_endpoints_in_scope``. Used by the missing-required-endpoints
# parametrize below.
_ENDPOINTS_CLOUD_SCHEMAS: list[type[BaseModel]] = [
    _SensitiveFilesArgs,
    _AdminPanelsArgs,
    _AzureSasTokenArgs,
    _GrafanaPathArgs,
    _KibanaPathArgs,
    _PortainerPathArgs,
    _ConsulVaultPathArgs,
]


class TestSchemaAcceptReject:
    # Schemas with a StrEnum filter parameter get a known-good acceptance
    # and an unknown-value rejection. Required-field schemas get a missing-
    # field rejection. Endpoint-taking schemas get a wrong-shape rejection.

    @pytest.mark.parametrize(
        ("schema_cls", "kwargs"),
        [
            # @pentest_tool acceptance cases
            (_SsrfArgs, {"endpoints": [], "payloads": ["aws-imds"]}),
            (_SsrfArgs, {"endpoints": []}),
            (_HeaderXssArgs, {"endpoints": [], "header_names": ["User-Agent"]}),
            (_PathTraversalArgs, {"endpoints": [], "payloads": ["unix-basic"]}),
            (_SstiArgs, {"endpoints": [], "payloads": ["jinja2"]}),
            (_OpenRedirectArgs, {"endpoints": [], "payloads": ["protocol-relative"]}),
            (_PromptInjectionArgs, {"endpoints": [], "payloads": ["override"]}),
            (_LdapInjectionArgs, {"endpoints": [], "payloads": ["auth-bypass"]}),
            (_CmdInjectionArgs, {"endpoints": [], "payloads": ["semicolon"]}),
            (_XxeArgs, {"endpoints": [], "payloads": ["linux-generic"]}),
            (
                _PrototypePollutionArgs,
                {"endpoints": [], "payloads": ["proto-dot"]},
            ),
            (_IdorArgs, {"endpoints": [], "attacks": ["boundary"]}),
            (
                _JwtCheckArgs,
                {
                    "token": "eyJ.x.y",
                    # endpoint is typed ``TargetEndpoint``; the URL must be
                    # in-scope per the programme fixture (which has
                    # ``*.example.com`` in its in-scope catalogue). Literal
                    # rather than f-string with target_apex: this is
                    # class-level parametrize data, evaluated at collection
                    # time when fixtures are not yet resolved.
                    "endpoint": {"url": "https://victim.example.com/api/me"},
                    "attacks": ["alg-none"],
                },
            ),
            (_NucleiScanArgs, {"endpoints": [], "tech_tags": ["wordpress"]}),
            (_SqlmapArgs, {"endpoints": []}),
            (_NosqliArgs, {"endpoints": []}),
            (_XssArgs, {"endpoints": []}),
            (_HppArgs, {"endpoints": []}),
            (_ErrorDisclosureArgs, {"endpoints": []}),
            (_CookieCheckArgs, {"recon_path": "recon.json"}),
            (_CsrfCheckArgs, {"recon_path": "recon.json"}),
            (_HeaderInjectionArgs, {"recon_path": "recon.json"}),
            (_HostHeaderArgs, {"recon_path": "recon.json"}),
            (_SourceMapsArgs, {"recon_path": "recon.json"}),
            (_SriCheckArgs, {"recon_path": "recon.json"}),
            # @cyber_tool cloud / infra acceptance cases.
            # The endpoint-taking shape accepts the empty list; the
            # hostname-taking shape's in-scope acceptance lives in
            # ``test_hostnames_schema_accepts_in_scope`` below where the
            # target_apex fixture makes test intent ("a real in-scope
            # hostname") readable at the call site.
            (_SensitiveFilesArgs, {"endpoints": []}),
            (_AdminPanelsArgs, {"endpoints": []}),
            (_AzureSasTokenArgs, {"endpoints": []}),
            (_GrafanaPathArgs, {"endpoints": []}),
            (_KibanaPathArgs, {"endpoints": []}),
            (_PortainerPathArgs, {"endpoints": []}),
            (_ConsulVaultPathArgs, {"endpoints": []}),
            # Empty-list acceptance is the safe shape: scope_filter runs on
            # non-empty values only, so an empty payload validates without
            # touching the workspace.
            (_S3CheckArgs, {"hostnames": []}),
            (_AzureBlobContainerArgs, {"hostnames": []}),
            (_ElasticsearchCheckArgs, {"hostnames": []}),
            (_CouchdbCheckArgs, {"hostnames": []}),
            (_RedisCheckArgs, {"hostnames": []}),
            (_MongodbCheckArgs, {"hostnames": []}),
            (_PostgresqlCheckArgs, {"hostnames": []}),
            (_MysqlCheckArgs, {"hostnames": []}),
            (_CpanelArgs, {"hostnames": []}),
            (_PleskArgs, {"hostnames": []}),
            (_DirectadminArgs, {"hostnames": []}),
            (_WebminArgs, {"hostnames": []}),
            (_GrafanaPortArgs, {"hostnames": []}),
            (_KibanaPortArgs, {"hostnames": []}),
            (_PortainerPortArgs, {"hostnames": []}),
            (_ConsulVaultPortArgs, {"hostnames": []}),
            # PT recon / save acceptance cases
            (_PtReconSubdomainsArgs, {"recon_path": "recon.json"}),
            (_PtReconSubdomainsArgs, {"recon_path": "recon.json", "host_filter": "api"}),
            (_PtReconEndpointsArgs, {"recon_path": "recon.json"}),
            (
                _PtReconEndpointsArgs,
                {
                    "recon_path": "recon.json",
                    "status": 200,
                    "tech": "wordpress",
                    "host_contains": "admin",
                    "offset": 0,
                    "limit": 25,
                },
            ),
            (_PtReconOpenPortsArgs, {"recon_path": "recon.json"}),
            # The host-restricted ``Recon Open Ports`` acceptance case lives
            # in a dedicated test method below (``test_recon_open_ports_*``)
            # because the ``host`` field is now ``FQDN``-typed and the
            # fixture-derived hostname makes test intent ("in-scope target")
            # readable at the call site rather than via an opaque literal.
            (_SaveFindingsArgs, {"findings": []}),
            # Shared workspace acceptance cases. List Run Files and
            # Read Attack Plan take no parameters - the empty payload is the
            # canonical call.
            (_ListRunFilesArgs, {}),
            (_ReadAttackForestArgs, {}),
            (_ReadRunFileArgs, {"relative_path": "recon.json"}),
        ],
    )
    def test_schema_accepts_known_input(
        self, schema_cls: type[BaseModel], kwargs: dict[str, object]
    ) -> None:
        """Known-good shapes pass model_validate without raising."""
        instance = schema_cls.model_validate(kwargs)
        assert isinstance(instance, schema_cls)

    # StrEnum-filtered probes - unknown payload / attack value must reject.
    @pytest.mark.parametrize(
        ("schema_cls", "field_name"),
        [
            (_SsrfArgs, "payloads"),
            (_HeaderXssArgs, "header_names"),
            (_PathTraversalArgs, "payloads"),
            (_SstiArgs, "payloads"),
            (_OpenRedirectArgs, "payloads"),
            (_PromptInjectionArgs, "payloads"),
            (_LdapInjectionArgs, "payloads"),
            (_CmdInjectionArgs, "payloads"),
            (_XxeArgs, "payloads"),
            (_PrototypePollutionArgs, "payloads"),
            (_IdorArgs, "attacks"),
            (_JwtCheckArgs, "attacks"),
        ],
    )
    def test_unknown_strenum_value_rejected(
        self, schema_cls: type[BaseModel], field_name: str, target_apex: str
    ) -> None:
        """An unknown StrEnum member must fail validation, not silently coerce."""
        base: dict[str, object] = {field_name: ["this-is-not-a-real-variant"]}
        if "endpoints" in schema_cls.model_fields:
            base["endpoints"] = []
        if "token" in schema_cls.model_fields:
            base["token"] = "eyJ.x.y"
        if "endpoint" in schema_cls.model_fields:
            # _JwtCheckArgs takes the typed ``Endpoint`` shape (not a bare
            # URL string); pass the minimum dict that validates so the test
            # stays focused on the unknown-StrEnum reject.
            base["endpoint"] = {"url": f"https://victim.{target_apex}/api/me"}
        with pytest.raises(ValidationError):
            schema_cls.model_validate(base)

    @pytest.mark.parametrize(
        "schema_cls",
        [
            _NucleiScanArgs,
            _SqlmapArgs,
            _SsrfArgs,
            _HeaderXssArgs,
            _PathTraversalArgs,
            _SstiArgs,
            _OpenRedirectArgs,
            _PromptInjectionArgs,
            _LdapInjectionArgs,
            _CmdInjectionArgs,
            _XxeArgs,
            _PrototypePollutionArgs,
            _IdorArgs,
            _NosqliArgs,
            _XssArgs,
            _HppArgs,
            _ErrorDisclosureArgs,
            # @cyber_tool cloud wrappers that take endpoints
            *_ENDPOINTS_CLOUD_SCHEMAS,
        ],
    )
    def test_missing_required_endpoints_rejected(self, schema_cls: type[BaseModel]) -> None:
        """``endpoints`` is required on every endpoint-taking PT typed-tool schema."""
        with pytest.raises(ValidationError):
            schema_cls.model_validate({})

    @pytest.mark.parametrize("schema_cls", _HOSTNAMES_CLOUD_SCHEMAS)
    def test_missing_required_hostnames_rejected(self, schema_cls: type[BaseModel]) -> None:
        """``hostnames`` is required on every hostname-taking cloud schema."""
        with pytest.raises(ValidationError):
            schema_cls.model_validate({})

    @pytest.mark.parametrize("schema_cls", _HOSTNAMES_CLOUD_SCHEMAS)
    def test_hostnames_schema_accepts_in_scope(
        self, schema_cls: type[BaseModel], target_apex: str
    ) -> None:
        """An in-scope hostname validates through the ``FQDN`` primitive.

        Uses ``target_apex`` so test intent ("a real in-scope target
        hostname") is readable at the call site rather than via an
        opaque literal. The wrapper-level scope filter runs at call
        time, not at schema validation, so this exercises only the
        ``FQDN`` primitive's RFC 1123 contract.
        """
        instance = schema_cls.model_validate({"hostnames": [f"api.{target_apex}"]})
        assert isinstance(instance, schema_cls)

    @pytest.mark.parametrize("schema_cls", _HOSTNAMES_CLOUD_SCHEMAS)
    def test_hostnames_schema_rejects_url(
        self, schema_cls: type[BaseModel], target_url: str
    ) -> None:
        """The ``FQDN`` primitive rejects a URL where a bare hostname
        is expected - passing a full URL trips the validator upstream of
        the wrapper, before any scope check or HTTP request."""
        with pytest.raises(ValidationError):
            schema_cls.model_validate({"hostnames": [target_url]})

    @pytest.mark.parametrize(
        "schema_cls",
        [
            _CookieCheckArgs,
            _CsrfCheckArgs,
            _HeaderInjectionArgs,
            _HostHeaderArgs,
            _SourceMapsArgs,
            _SriCheckArgs,
            # PT recon wrappers - all take a required ``recon_path``
            _PtReconSubdomainsArgs,
            _PtReconEndpointsArgs,
            _PtReconOpenPortsArgs,
        ],
    )
    def test_missing_required_recon_path_rejected(self, schema_cls: type[BaseModel]) -> None:
        """``recon_path`` is required on every recon-path-taking PT typed-tool schema."""
        with pytest.raises(ValidationError):
            schema_cls.model_validate({})

    def test_jwt_requires_both_token_and_endpoint(self, endpoint) -> None:
        """JWT check needs the raw token and the validating endpoint.

        Uses the conftest ``endpoint`` fixture for the typed-Endpoint
        payload so test intent ("a real, in-scope target endpoint") is
        readable at the call site rather than via a hand-rolled URL
        literal.
        """
        with pytest.raises(ValidationError):
            _JwtCheckArgs.model_validate({"token": "eyJ.x.y"})
        with pytest.raises(ValidationError):
            _JwtCheckArgs.model_validate({"endpoint": endpoint.model_dump(mode="json")})

    def test_jwt_rejects_malformed_endpoint(self, endpoint, target_apex) -> None:
        """The typed ``Endpoint`` validates URL well-formedness upstream of
        the JWT replay - a string where an Endpoint dict is required
        rejects, as does an Endpoint dict whose URL is malformed."""
        with pytest.raises(ValidationError):
            _JwtCheckArgs.model_validate(
                {"token": "eyJ.x.y", "endpoint": f"https://victim.{target_apex}/api"}
            )
        with pytest.raises(ValidationError):
            _JwtCheckArgs.model_validate({"token": "eyJ.x.y", "endpoint": {"url": "not-a-url"}})
        # The conftest endpoint fixture is intentionally valid; this asserts
        # the happy path stays accepting alongside the rejects above.
        _JwtCheckArgs.model_validate(
            {"token": "eyJ.x.y", "endpoint": endpoint.model_dump(mode="json")}
        )

    def test_save_findings_requires_findings(self) -> None:
        """``Save Findings`` rejects an empty payload - ``findings`` has no default."""
        with pytest.raises(ValidationError):
            _SaveFindingsArgs.model_validate({})

    def test_read_run_file_requires_relative_path(self) -> None:
        """``Read Run File`` rejects an empty payload - ``relative_path`` is required."""
        with pytest.raises(ValidationError):
            _ReadRunFileArgs.model_validate({})

    def test_save_findings_rejects_mis_shaped_finding(self) -> None:
        """A dict that does not validate as ``RawFinding`` rejects upstream of
        the wrapper - the whole point of the typed ``list[RawFinding]``
        parameter is the schema reject before findings.json is written."""
        with pytest.raises(ValidationError):
            _SaveFindingsArgs.model_validate({"findings": [{"not_a_real_field": "x"}]})

    def test_recon_open_ports_accepts_victim_host(self, target_url: str) -> None:
        """``Recon Open Ports`` accepts a bare hostname filter.

        The ``host`` field is ``FQDN``-typed; using the ``target_url``
        fixture (the conftest's in-scope-target handle) and stripping the
        scheme keeps the test intent readable at the call site rather than
        via an opaque ``api.example.com`` literal.
        """
        from urllib.parse import urlparse

        host = urlparse(target_url).hostname
        _PtReconOpenPortsArgs.model_validate({"recon_path": "recon.json", "host": host})

    def test_recon_open_ports_rejects_url_in_host(self, target_url: str) -> None:
        """The ``FQDN`` primitive rejects a URL where a bare hostname
        is expected - ``target_url`` carries the ``https://`` scheme, so
        passing it directly trips the validator upstream of the wrapper."""
        with pytest.raises(ValidationError):
            _PtReconOpenPortsArgs.model_validate({"recon_path": "recon.json", "host": target_url})
