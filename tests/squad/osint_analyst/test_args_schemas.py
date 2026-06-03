"""
tests/squad/osint_analyst/test_args_schemas.py - contract tests for the explicit Pydantic
``args_schema`` every OSINT Analyst ``@cyber_tool`` wrapper carries.

Sibling of ``test_pt_args_schemas.py``: same shape of structural and
accept / reject checks, scoped to the OSINT Analyst's tool surface.

OSINT tools fire external recon (subfinder, httpx, nmap, testssl.sh,
ffuf, crt.sh, waybackurls, dnsx, LLM endpoint detection) against in-
scope hosts. The "live programmes, mis-call costs money" framing
applies here plus a recon-specific scope-leak risk: a mis-targeted
``host_filter`` or wrong ``host_contains`` substring can pull a
sibling programme's endpoints into the run and silently corrupt every
downstream stage. Filter-parameter discipline is the bulk of what the
per-field descriptions are doing.

The generic contract loop (tool wires the explicit schema, every field
has a description, closed-world mapping) lives in
``tests/squad/_contract_assertions.py`` and is exercised below by
parametrising over ``MEMBER.schemas``. Agent-specific cases (the
hostname-rejection sweep, the URL / apex / takeover acceptance cases,
required-field rejections) stay in this file.
"""

from __future__ import annotations

from urllib.parse import urlparse

import pytest
from pydantic import BaseModel, ValidationError

from squad.osint_analyst import (
    MEMBER,
    _AnnotateHostArgs,
    _DiscoverHistoricalUrlsArgs,
    _DiscoverLlmEndpointsArgs,
    _DiscoverSubdomainsArgs,
    _DiscoverTakeoverCandidatesArgs,
    _DiscoverWebpagesArgs,
    _FinaliseReconArgs,
    _ListEndpointsArgs,
    _ListOpenPortsArgs,
    _ListSubdomainsArgs,
    _ListUncoveredHostsArgs,
    _OsintLookupCweArgs,
    _OsintLookupOwaspArgs,
    _RunInitialSweepArgs,
)
from squad.tools.workspace_tools import (
    _ListRunFilesArgs,
    _ReadRunFileArgs,
)
from tests.squad._contract_assertions import (
    assert_closed_world_mapping,
    assert_field_descriptions_present,
    assert_tool_wires_explicit_schema,
)

pytestmark = pytest.mark.unit


# Every schema in this file with a typed-target field
# (``TargetFQDNs`` / ``TargetEndpoints`` / ``TargetFQDN`` /
# ``TargetEndpoint``) runs its ``AfterValidator`` during
# ``model_validate`` - and that validator calls ``current_programme()``.
# Autousing ``programme_in_workspace`` stages a programme into the
# rundir so every schema-shape test has the run-time context the
# validator needs.
@pytest.fixture(autouse=True)
def _seed_programme(programme_in_workspace):
    return programme_in_workspace


def _annotate_host_base(hostname: str) -> dict[str, object]:
    """Minimal valid kwargs for _AnnotateHostArgs, parameterised by hostname.

    Centralised so the fixture-derived hostname flows in from one place and
    each rejection test stays focused on the field it is exercising.
    """
    return {
        "hostname": hostname,
        "role": "api",
        "priority": "high",
        "notes": "Production REST API surface; warrants careful probing.",
    }


class TestOsintArgsSchemaContracts:
    @pytest.mark.parametrize("tool_name", sorted(MEMBER.schemas))
    def test_tool_wires_explicit_schema(self, tool_name: str) -> None:
        assert_tool_wires_explicit_schema(MEMBER, tool_name)

    @pytest.mark.parametrize(
        ("tool_name", "schema_cls"),
        sorted(MEMBER.schemas.items()),
        ids=sorted(MEMBER.schemas),
    )
    def test_every_field_has_description(self, tool_name: str, schema_cls: type[BaseModel]) -> None:
        assert_field_descriptions_present(tool_name, schema_cls)

    def test_closed_world_mapping(self) -> None:
        assert_closed_world_mapping(MEMBER)


class TestSchemaAcceptReject:
    """Accept / reject contract per schema.

    The parametrize below carries cases that do not involve a hostname or
    URL - those use the conftest ``target_url`` / ``bystander_url`` /
    ``callback_url`` domain fixtures via the dedicated test methods further
    down, so test intent ("this is the in-scope target") is readable at the
    call site rather than via opaque ``example.com`` literals.
    """

    @pytest.mark.parametrize(
        ("schema_cls", "kwargs"),
        [
            (_RunInitialSweepArgs, {}),
            (_ListSubdomainsArgs, {}),
            (
                _ListSubdomainsArgs,
                {"attack_graph_path": "attack_graph.json", "host_filter": "api"},
            ),
            (_ListEndpointsArgs, {}),
            (
                _ListEndpointsArgs,
                {"status": 200, "tech": "wordpress", "host_contains": "admin", "limit": 25},
            ),
            (_ListOpenPortsArgs, {}),
            (_OsintLookupCweArgs, {"cwe_id": 79}),
            (_OsintLookupOwaspArgs, {"query": "csrf"}),
            (_ListUncoveredHostsArgs, {}),
            (_FinaliseReconArgs, {}),
            # Shared workspace acceptance cases. List Run Files takes
            # no parameters; Read Run File needs a relative path.
            (_ListRunFilesArgs, {}),
            (_ReadRunFileArgs, {"relative_path": "recon.json"}),
        ],
    )
    def test_schema_accepts_known_input(
        self, schema_cls: type[BaseModel], kwargs: dict[str, object]
    ) -> None:
        """Known-good shapes pass model_validate without raising."""
        instance = schema_cls.model_validate(kwargs)
        assert isinstance(instance, schema_cls)

    # URL / hostname-taking schemas use the conftest domain fixtures so test
    # intent is readable at the call site. Each schema below has a dedicated
    # method rather than a parametrize entry because parametrize literals
    # cannot consume fixtures.

    def test_recon_open_ports_accepts_victim_host(self, target_url: str) -> None:
        """List Open Ports accepts a real hostname filter."""
        host = urlparse(target_url).hostname
        _ListOpenPortsArgs.model_validate({"host": host})

    def test_cert_transparency_accepts_target_apex(self, target_url: str) -> None:
        """Discover Subdomains takes the apex domain of the in-scope target."""
        host = urlparse(target_url).hostname or ""
        apex = host.split(".", 1)[-1] if "." in host else host
        _DiscoverSubdomainsArgs.model_validate({"domain": apex})

    def test_historical_urls_accepts_target_apex(self, target_url: str) -> None:
        """Discover Historical URLs takes the apex domain of the in-scope target."""
        host = urlparse(target_url).hostname or ""
        apex = host.split(".", 1)[-1] if "." in host else host
        _DiscoverHistoricalUrlsArgs.model_validate({"domain": apex})

    def test_probe_hostnames_accepts_victim_hostname(self, target_url: str) -> None:
        """Discover Webpages takes a list of hostnames - no programme handle.

        The wrapper-level ``scope_filter`` sources the Programme from
        the workspace (``current_programme()`` -> ``programme.json``),
        so the schema does not require a per-call handle.
        """
        _DiscoverWebpagesArgs.model_validate({"hostnames": [urlparse(target_url).hostname]})

    def test_detect_takeover_candidates_accepts_bystander_hostname(
        self, bystander_url: str
    ) -> None:
        """Discover Takeover Candidates models the case where a CNAME dangles to a
        bystander - the ``bystander_url`` fixture is the conventional handle
        for an out-of-scope target. The wrapper-level scope filter drops
        the bystander before any DNS traffic fires."""
        _DiscoverTakeoverCandidatesArgs.model_validate(
            {"hostnames": [urlparse(bystander_url).hostname]}
        )

    def test_annotate_host_accepts_victim_hostname(self, target_url: str) -> None:
        """Annotate Host takes a hostname plus role / priority / notes / tech."""
        host = urlparse(target_url).hostname or ""
        _AnnotateHostArgs.model_validate(
            {
                **_annotate_host_base(host),
                "detected_tech": ["nginx"],
            }
        )

    def test_llm_detection_accepts_populated_endpoint_list(self, endpoint) -> None:
        """Discover LLM Endpoints accepts the realistic ``Endpoint`` shape.

        The conftest ``endpoint`` fixture is the canonical Endpoint instance;
        using it here exercises the Endpoint model's own validation path as
        part of the schema contract.
        """
        instance = _DiscoverLlmEndpointsArgs.model_validate(
            {"endpoints": [endpoint.model_dump(mode="json")]}
        )
        assert len(instance.endpoints) == 1
        assert instance.endpoints[0].url == endpoint.url

    # Required-field rejections. Each schema below has at least one
    # required field; missing it must fail validation.
    @pytest.mark.parametrize(
        "schema_cls",
        [
            _DiscoverSubdomainsArgs,  # domain required
            _DiscoverHistoricalUrlsArgs,  # domain required
            _DiscoverLlmEndpointsArgs,  # endpoints required
            _DiscoverWebpagesArgs,  # hostnames required (scope_filter sources Programme)
            _DiscoverTakeoverCandidatesArgs,  # hostnames required (scope_filter sources Programme)
            _OsintLookupCweArgs,  # cwe_id required
            _OsintLookupOwaspArgs,  # query required
            _AnnotateHostArgs,  # hostname / role / priority / notes required
        ],
    )
    def test_missing_required_field_rejected(self, schema_cls: type[BaseModel]) -> None:
        """At least one required field is missing: model_validate must fail."""
        with pytest.raises(ValidationError):
            schema_cls.model_validate({})

    def test_annotate_host_requires_core_fields(self, target_url: str) -> None:
        """hostname / role / priority / notes are all required."""
        base = _annotate_host_base(urlparse(target_url).hostname or "")
        for missing in ("hostname", "role", "priority", "notes"):
            kwargs = {k: v for k, v in base.items() if k != missing}
            with pytest.raises(ValidationError):
                _AnnotateHostArgs.model_validate(kwargs)

    def test_annotate_host_rejects_unknown_role_and_priority(self, target_url: str) -> None:
        """role and priority are typed as HostRole / HostPriority StrEnums.

        Unknown values reject upstream of the wrapper rather than in the
        body's ``HostRole(role)`` / ``HostPriority(priority)`` coercion.
        """
        base = _annotate_host_base(urlparse(target_url).hostname or "")
        with pytest.raises(ValidationError):
            _AnnotateHostArgs.model_validate({**base, "role": "not-a-real-role"})
        with pytest.raises(ValidationError):
            _AnnotateHostArgs.model_validate({**base, "priority": "urgent"})

    # FQDN-typed fields. Every schema below
    # carries at least one ``FQDN`` field; passing a URL / port / path
    # rejects upstream, before the scope filter sees the value.
    # tests/models/test_primitives.py TestFQDN covers the validator exhaustively;
    # this method asserts the OSINT schemas actually wire it, with each
    # malformed case derived from ``target_url`` so the deliberately broken
    # input is recognisably "the in-scope target, mis-shaped" rather than
    # an opaque literal.
    def test_hostname_field_rejects_malformed_input(self, target_url: str) -> None:
        host = urlparse(target_url).hostname or ""
        cases: list[tuple[type[BaseModel], str, object, dict[str, object]]] = [
            (_DiscoverSubdomainsArgs, "domain", f"https://{host}", {}),
            (_DiscoverHistoricalUrlsArgs, "domain", f"{host}:8080", {}),
            (_ListOpenPortsArgs, "host", f"{host}/path", {}),
            (_DiscoverWebpagesArgs, "hostnames", [f"https://{host}"], {}),
            (_DiscoverTakeoverCandidatesArgs, "hostnames", [f"{host}:9000"], {}),
        ]
        for schema_cls, field, value, base in cases:
            with pytest.raises(ValidationError):
                schema_cls.model_validate({**base, field: value})

    def test_annotate_host_hostname_rejects_url(self, target_url: str) -> None:
        """Annotate Host's hostname is FQDN-typed; passing the full URL fails."""
        with pytest.raises(ValidationError):
            _AnnotateHostArgs.model_validate(_annotate_host_base(target_url))

    def test_hostname_fields_lowercase_input(self, target_url: str) -> None:
        """FQDN validator lowercases - the schema returns the normalised form."""
        host = (urlparse(target_url).hostname or "").upper()
        validated = _AnnotateHostArgs.model_validate(_annotate_host_base(host))
        assert validated.hostname == host.lower()
