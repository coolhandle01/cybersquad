"""tests/squad/penetration_tester/test_cloud_wrappers.py - the typed cloud
wrappers on the Penetration Tester.

Roughly two dozen near-identical cloud wrappers (S3 / Azure / databases /
panels / dashboards / service-discovery) each take a typed target and
scope-filter at the wrapper before forwarding to ``check_X``. Rather than
a bespoke test per wrapper, the parametrize tables below cover the
wrapper-level scope-filter + helper-forwarding contract for all of them at
once, split by body shape (iterating vs list-passing for FQDN inputs;
endpoint-passing for the rest). The closed-world checks refuse a new cloud
wrapper landing without being added to its table. The bespoke probe /
recon / findings wrapper tests live in ``test_tools.py``.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit


# FQDN-passing cloud wrappers split by body shape: each takes
# ``list[FQDN]`` and scope-filters at the wrapper, but the body
# differs in how it forwards to ``check_X``.
#
# - Iterating: the databases call ``check_X(host)`` per host inside a
#   loop. When the filtered list is empty, ``check_X`` is never called.
# - List-passing: panels / dashboards / consul / storage call
#   ``check_X(hostnames)`` once with the whole list. The downstream
#   helper handles empty internally - the per-hostname HTTP probe
#   never fires - but ``check_X`` itself IS called with ``[]``.
#
# Splitting per body shape lets each parametrize assert exactly what
# the body does, rather than a both-shapes "or" assertion.
#
# These two tables are hand-maintained constants rather than derived
# from ``MEMBER.schemas``: the iterating vs list-passing distinction
# is a body-shape property the args_schema cannot express. They also
# carry the ``check_fn_path`` dotted string each test patches into,
# which is body-internal and isn't on any registry. The closed-world
# check ``test_hostname_wrapper_tables_cover_every_schema`` below
# refuses a new hostname-taking wrapper landing without being added
# to one of the two tables; same for the endpoint table further down.
_HOSTNAME_PASSING_ITERATING_WRAPPERS: list[tuple[str, str]] = [
    ("elasticsearch_tool", "squad.penetration_tester.tools.cloud.databases.check_elasticsearch"),
    ("couchdb_tool", "squad.penetration_tester.tools.cloud.databases.check_couchdb"),
    ("redis_tool", "squad.penetration_tester.tools.cloud.databases.check_redis"),
    ("mongodb_tool", "squad.penetration_tester.tools.cloud.databases.check_mongodb"),
    ("postgresql_tool", "squad.penetration_tester.tools.cloud.databases.check_postgresql"),
    ("mysql_tool", "squad.penetration_tester.tools.cloud.databases.check_mysql"),
]

_HOSTNAME_PASSING_LIST_WRAPPERS: list[tuple[str, str]] = [
    ("s3_check_tool", "squad.penetration_tester.tools.cloud.storage.check_s3_buckets"),
    (
        "azure_blob_container_check_tool",
        "squad.penetration_tester.tools.cloud.storage.check_azure_blob_containers",
    ),
    ("cpanel_tool", "squad.penetration_tester.tools.cloud.panels.check_cpanel"),
    ("plesk_tool", "squad.penetration_tester.tools.cloud.panels.check_plesk"),
    ("directadmin_tool", "squad.penetration_tester.tools.cloud.panels.check_directadmin"),
    ("webmin_tool", "squad.penetration_tester.tools.cloud.panels.check_webmin"),
    (
        "grafana_port_check_tool",
        "squad.penetration_tester.tools.cloud.dashboards.check_grafana_ports",
    ),
    (
        "kibana_port_check_tool",
        "squad.penetration_tester.tools.cloud.dashboards.check_kibana_ports",
    ),
    (
        "portainer_port_check_tool",
        "squad.penetration_tester.tools.cloud.dashboards.check_portainer_ports",
    ),
    (
        "consul_vault_port_check_tool",
        "squad.penetration_tester.tools.cloud.service_discovery.check_consul_vault_ports",
    ),
]


def _resolve_check_fn(check_fn_path: str) -> tuple[object, str]:
    import importlib

    module_path, attr = check_fn_path.rsplit(".", 1)
    return importlib.import_module(module_path), attr


def test_hostname_wrapper_tables_cover_every_hostname_taking_schema() -> None:
    """Closed-world: the two hostname-passing tables together cover every
    PT cloud wrapper whose schema declares a ``hostnames`` field.

    The split into iterating vs list-passing is a body-shape distinction
    that the args_schema cannot express, so the tables are hand-maintained
    constants - this check refuses a new hostname-taking wrapper landing
    without being added to one of the two tables.
    """
    import squad.penetration_tester as pt_module

    hostname_schemas = {
        tool_name
        for tool_name, schema_cls in pt_module.MEMBER.schemas.items()
        if "hostnames" in schema_cls.model_fields
    }
    table_display_names = {
        getattr(pt_module, var_name).name
        for var_name, _ in _HOSTNAME_PASSING_ITERATING_WRAPPERS + _HOSTNAME_PASSING_LIST_WRAPPERS
    }
    assert hostname_schemas == table_display_names, (
        "FQDN-passing wrapper tables drifted from MEMBER.schemas: "
        f"in schemas but not tables = {hostname_schemas - table_display_names}; "
        f"in tables but not schemas = {table_display_names - hostname_schemas}"
    )


class TestFQDNIteratingWrappers:
    """Databases iterate the supplied hostnames and call
    ``check_X(host)`` per host. The wrapper-level scope_filter drops
    OOS hosts before the loop body runs, so on an empty filtered list
    the loop is a no-op and ``check_X`` is never called."""

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _HOSTNAME_PASSING_ITERATING_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _HOSTNAME_PASSING_ITERATING_WRAPPERS],
    )
    def test_wrapper_calls_check_fn_per_in_scope_host(
        self,
        tool_name: str,
        check_fn_path: str,
        programme_in_workspace,
        raw_finding_low,
        target_apex: str,
    ) -> None:
        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        in_scope_host = f"api.{target_apex}"

        check_module, check_attr = _resolve_check_fn(check_fn_path)
        with patch.object(check_module, check_attr, return_value=[raw_finding_low]) as mcheck:
            result = wrapper.func([in_scope_host])

        assert result == [raw_finding_low]
        mcheck.assert_called_once_with(in_scope_host)

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _HOSTNAME_PASSING_ITERATING_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _HOSTNAME_PASSING_ITERATING_WRAPPERS],
    )
    def test_wrapper_skips_check_fn_when_all_hosts_out_of_scope(
        self,
        tool_name: str,
        check_fn_path: str,
        programme_in_workspace,
        bystander_url: str,
        invoke_tool,
    ) -> None:
        from urllib.parse import urlparse

        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        oos_host = urlparse(bystander_url).hostname

        check_module, check_attr = _resolve_check_fn(check_fn_path)
        with patch.object(check_module, check_attr, return_value=[]) as mcheck:
            result = invoke_tool(wrapper, hostnames=[oos_host])

        assert result == []
        mcheck.assert_not_called()


class TestFQDNListPassingWrappers:
    """Panels / dashboards / consul / storage call ``check_X(hostnames)``
    once with the filtered list. When everything filters out, the
    wrapper calls ``check_X([])`` - the helper handles empty internally
    and no per-hostname HTTP probe fires."""

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _HOSTNAME_PASSING_LIST_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _HOSTNAME_PASSING_LIST_WRAPPERS],
    )
    def test_wrapper_forwards_in_scope_hostnames_to_check_fn(
        self,
        tool_name: str,
        check_fn_path: str,
        programme_in_workspace,
        raw_finding_low,
        target_apex: str,
    ) -> None:
        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        in_scope_host = f"api.{target_apex}"

        check_module, check_attr = _resolve_check_fn(check_fn_path)
        with patch.object(check_module, check_attr, return_value=[raw_finding_low]) as mcheck:
            result = wrapper.func([in_scope_host])

        assert result == [raw_finding_low]
        mcheck.assert_called_once_with([in_scope_host])

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _HOSTNAME_PASSING_LIST_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _HOSTNAME_PASSING_LIST_WRAPPERS],
    )
    def test_wrapper_calls_check_fn_with_empty_list_when_out_of_scope(
        self,
        tool_name: str,
        check_fn_path: str,
        programme_in_workspace,
        bystander_url: str,
        invoke_tool,
    ) -> None:
        from urllib.parse import urlparse

        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        oos_host = urlparse(bystander_url).hostname

        check_module, check_attr = _resolve_check_fn(check_fn_path)
        with patch.object(check_module, check_attr, return_value=[]) as mcheck:
            result = invoke_tool(wrapper, hostnames=[oos_host])

        assert result == []
        mcheck.assert_called_once_with([])
        # Sanity-check: the OOS host never reached the helper.
        passed = mcheck.call_args[0][0]
        assert oos_host not in passed, (
            f"{tool_name}: scope_filter let the OOS host reach check_X; got {passed!r}"
        )


def test_endpoint_driven_cloud_table_covers_every_cloud_endpoint_wrapper() -> None:
    """Closed-world: the endpoint-passing table covers every PT cloud
    wrapper whose schema declares an ``endpoints`` field.

    Probe wrappers (Nuclei, SQLMap, SSRF, ...) also take ``endpoints``,
    so the cloud-only subset is selected by ``func.__module__`` starting
    with ``squad.penetration_tester.tools.cloud.``. The split is deliberate -
    probe wrappers have their own bespoke tests in ``test_tools.py``.
    """
    import squad.penetration_tester as pt_module

    cloud_endpoint_tools = {
        tool.name
        for tool in pt_module.MEMBER.tools
        if tool.func.__module__.startswith("squad.penetration_tester.tools.cloud.")
        and "endpoints" in tool.args_schema.model_fields
    }
    table_display_names = {
        getattr(pt_module, var_name).name for var_name, _ in _ENDPOINT_DRIVEN_CLOUD_WRAPPERS
    }
    assert cloud_endpoint_tools == table_display_names, (
        "Endpoint-driven cloud wrapper table drifted from MEMBER.tools: "
        f"in cloud / endpoints but not table = {cloud_endpoint_tools - table_display_names}; "
        f"in table but not cloud / endpoints = {table_display_names - cloud_endpoint_tools}"
    )


_ENDPOINT_DRIVEN_CLOUD_WRAPPERS: list[tuple[str, str]] = [
    (
        "sensitive_files_tool",
        "squad.penetration_tester.tools.cloud.web_content.check_sensitive_files",
    ),
    ("admin_panels_tool", "squad.penetration_tester.tools.cloud.web_content.check_admin_panels"),
    (
        "azure_sas_token_check_tool",
        "squad.penetration_tester.tools.cloud.storage.check_azure_sas_tokens",
    ),
    (
        "grafana_path_check_tool",
        "squad.penetration_tester.tools.cloud.dashboards.check_grafana_paths",
    ),
    (
        "kibana_path_check_tool",
        "squad.penetration_tester.tools.cloud.dashboards.check_kibana_paths",
    ),
    (
        "portainer_path_check_tool",
        "squad.penetration_tester.tools.cloud.dashboards.check_portainer_paths",
    ),
    (
        "consul_vault_path_check_tool",
        "squad.penetration_tester.tools.cloud.service_discovery.check_consul_vault_paths",
    ),
]


class TestEndpointWrapperPassThrough:
    """Each endpoint-passing cloud wrapper takes ``list[Endpoint]``,
    scope-filters via ``filter_endpoints_in_scope`` on the URL host,
    and forwards the survivors to ``check_X``. Pins the wrapper-level
    pass-through and the scope-filter guard for all 6 at once."""

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _ENDPOINT_DRIVEN_CLOUD_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _ENDPOINT_DRIVEN_CLOUD_WRAPPERS],
    )
    def test_wrapper_passes_in_scope_endpoints_to_check_fn(
        self,
        tool_name: str,
        check_fn_path: str,
        programme_in_workspace,
        endpoint,
        raw_finding_low,
    ) -> None:
        import importlib

        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        check_module_path, check_attr = check_fn_path.rsplit(".", 1)
        check_module = importlib.import_module(check_module_path)
        with patch.object(check_module, check_attr, return_value=[raw_finding_low]) as mcheck:
            result = wrapper.func([endpoint.model_dump(mode="json")])

        assert result == [raw_finding_low]
        # The wrapper re-validated the dict back into an Endpoint instance
        # before handing it to check_X.
        mcheck.assert_called_once()
        passed_endpoints = mcheck.call_args[0][0]
        assert len(passed_endpoints) == 1
        assert passed_endpoints[0].url == endpoint.url

    @pytest.mark.parametrize(
        ("tool_name", "check_fn_path"),
        _ENDPOINT_DRIVEN_CLOUD_WRAPPERS,
        ids=[name.removesuffix("_tool") for name, _ in _ENDPOINT_DRIVEN_CLOUD_WRAPPERS],
    )
    def test_wrapper_drops_out_of_scope_endpoints(
        self,
        tool_name: str,
        check_fn_path: str,
        programme_in_workspace,
        bystander_url: str,
        invoke_tool,
    ) -> None:
        """The args_schema's ``TargetEndpoints`` validator drops
        endpoints whose host is outside the programme's structured
        scope before the wrapper body runs; ``check_X`` still receives
        the (empty) filtered list but the per-endpoint HTTP probe
        never fires."""
        import importlib

        import squad.penetration_tester as pt_module

        wrapper = getattr(pt_module, tool_name)
        oos_endpoint = {"url": bystander_url, "status_code": 200}

        check_module_path, check_attr = check_fn_path.rsplit(".", 1)
        check_module = importlib.import_module(check_module_path)
        with patch.object(check_module, check_attr, return_value=[]) as mcheck:
            result = invoke_tool(wrapper, endpoints=[oos_endpoint])

        assert result == []
        for call in mcheck.call_args_list:
            args = call.args[0] if call.args else None
            assert args == [], (
                f"{tool_name}: scope_filter let the OOS endpoint reach check_X; "
                f"got call args {args!r}"
            )
