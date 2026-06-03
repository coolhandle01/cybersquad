"""
Monitoring / orchestration dashboard probes - Grafana, Kibana,
Portainer. Each dashboard splits into two wrappers so the agent picks
each target type explicitly and each wrapper carries a single
``scope_filter``:

- ``<engine> Port Check`` - takes ``list[FQDN]`` (the host:port
  pairs from recon) and probes the dashboard's signature port.
- ``<engine> Path Check`` - takes ``list[Endpoint]`` (the live origins
  from recon) and probes the reverse-proxy path on each.

Default-credential / anonymous-access flavours are reported with the
specific exposure mode.
"""

from pydantic import BaseModel, Field

from models import FQDN, Endpoint, RawFinding
from squad import cyber_tool
from squad.penetration_tester.tools._decorator import _parse_endpoints
from tools.cloud import (
    check_grafana_paths,
    check_grafana_ports,
    check_kibana_paths,
    check_kibana_ports,
    check_portainer_paths,
    check_portainer_ports,
)
from tools.recon.scope import TargetEndpoints, TargetFQDNs


class _GrafanaPortArgs(BaseModel):
    """Explicit args_schema for the Grafana Port Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs showing port 3000 open, hostnames whose"
            " technologies mention Grafana, or hostnames on a DevOps /"
            " SRE-heavy target. Probes Grafana on port 3000. The"
            " wrapper's scope filter drops out-of-scope hostnames before"
            " any probe."
        ),
    )


@cyber_tool("Grafana Port Check", args_schema=_GrafanaPortArgs)
def grafana_port_check_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check for an exposed Grafana metrics dashboard on port 3000 on each
    supplied hostname.

    Pick hostnames from the Recon Open Ports slicer where 3000 shows
    open, or where technologies mention Grafana, or when the target is
    DevOps / SRE-heavy. The wrapper scope-filters the list.
    """
    return list(check_grafana_ports(hostnames))


class _GrafanaPathArgs(BaseModel):
    """Explicit args_schema for the Grafana Path Check tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Endpoint objects. Probes /grafana on each origin (the tool"
            " deduplicates by origin). Fire when the target reverse-"
            "proxies metrics dashboards behind a normal HTTP endpoint."
            " The wrapper's scope filter drops endpoints whose host is"
            " outside the selected programme's structured scope."
        ),
    )


@cyber_tool("Grafana Path Check", args_schema=_GrafanaPathArgs)
def grafana_path_check_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Check for Grafana reverse-proxied at /grafana on each supplied origin.

    Pick a representative set of live endpoints from Recon Endpoints; the
    tool deduplicates by origin. Use when the target reverse-proxies its
    metrics dashboards behind a normal HTTP endpoint.
    """
    return list(check_grafana_paths(_parse_endpoints(endpoints)))


class _KibanaPortArgs(BaseModel):
    """Explicit args_schema for the Kibana Port Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs showing port 5601 (Kibana) or 9200 (Elasticsearch"
            " stack) open, or hostnames whose technologies mention Kibana"
            " or Elasticsearch. Probes Kibana on port 5601. The wrapper's"
            " scope filter drops out-of-scope hostnames before any probe."
        ),
    )


@cyber_tool("Kibana Port Check", args_schema=_KibanaPortArgs)
def kibana_port_check_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check for an exposed Kibana log / data visualisation dashboard on
    port 5601 on each supplied hostname.

    Pick hostnames from the Recon Open Ports slicer where 5601 or 9200
    shows open, or where technologies mention Kibana / Elasticsearch.
    The wrapper scope-filters the list.
    """
    return list(check_kibana_ports(hostnames))


class _KibanaPathArgs(BaseModel):
    """Explicit args_schema for the Kibana Path Check tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Endpoint objects. Probes /kibana on each origin (the tool"
            " deduplicates by origin). Fire when the target reverse-"
            "proxies its observability stack behind a normal HTTP"
            " endpoint. The wrapper's scope filter drops endpoints whose"
            " host is outside the selected programme's structured scope."
        ),
    )


@cyber_tool("Kibana Path Check", args_schema=_KibanaPathArgs)
def kibana_path_check_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Check for Kibana reverse-proxied at /kibana on each supplied origin.

    Pick a representative set of live endpoints from Recon Endpoints; the
    tool deduplicates by origin. Use when the target reverse-proxies its
    observability stack behind a normal HTTP endpoint.
    """
    return list(check_kibana_paths(_parse_endpoints(endpoints)))


class _PortainerPortArgs(BaseModel):
    """Explicit args_schema for the Portainer Port Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs showing port 9000 open, or hostnames whose"
            " technologies mention Docker / containerised infrastructure."
            " Probes Portainer on port 9000. The wrapper's scope filter"
            " drops out-of-scope hostnames before any probe."
        ),
    )


@cyber_tool("Portainer Port Check", args_schema=_PortainerPortArgs)
def portainer_port_check_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check for an exposed Portainer Docker management UI on port 9000 on
    each supplied hostname.

    Pick hostnames from the Recon Open Ports slicer where 9000 shows
    open, or where technologies mention Docker / containerised
    infrastructure. The wrapper scope-filters the list.
    """
    return list(check_portainer_ports(hostnames))


class _PortainerPathArgs(BaseModel):
    """Explicit args_schema for the Portainer Path Check tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Endpoint objects. Probes /portainer on each origin (the tool"
            " deduplicates by origin). Fire when the target reverse-"
            "proxies container-management UIs behind a normal HTTP"
            " endpoint. The wrapper's scope filter drops endpoints whose"
            " host is outside the selected programme's structured scope."
        ),
    )


@cyber_tool("Portainer Path Check", args_schema=_PortainerPathArgs)
def portainer_path_check_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Check for Portainer reverse-proxied at /portainer on each supplied
    origin.

    Pick a representative set of live endpoints from Recon Endpoints; the
    tool deduplicates by origin. Use when the target reverse-proxies its
    container-management UI behind a normal HTTP endpoint.
    """
    return list(check_portainer_paths(_parse_endpoints(endpoints)))
