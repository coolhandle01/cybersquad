"""
Service-discovery exposure probes - HashiCorp Consul and Vault
unauthenticated UIs. Splits into two wrappers (port and path) so each
takes a single typed target list and a single ``scope_filter``:

- ``Consul/Vault Port Check`` - probes the consul-ui (port 8500) and
  vault-ui (port 8200) signature endpoints on each supplied hostname.
- ``Consul/Vault Path Check`` - probes /consul/ui and /vault/ui
  reverse-proxy paths on each supplied origin.
"""

from pydantic import BaseModel, Field

from models import FQDN, Endpoint, RawFinding
from squad import cyber_tool
from squad.penetration_tester.tools._decorator import _parse_endpoints
from tools.cloud import check_consul_vault_paths, check_consul_vault_ports
from tools.recon.scope import TargetEndpoints, TargetFQDNs


class _ConsulVaultPortArgs(BaseModel):
    """Explicit args_schema for the Consul/Vault Port Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs showing port 8500 (Consul) or 8200 (Vault) open,"
            " or hostnames on a cloud-native / microservices target."
            " Probes Consul UI on 8500 and Vault UI on 8200. The"
            " wrapper's scope filter drops out-of-scope hostnames before"
            " any probe."
        ),
    )


@cyber_tool("Consul/Vault Port Check", args_schema=_ConsulVaultPortArgs)
def consul_vault_port_check_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check for an exposed HashiCorp Consul UI (port 8500) or Vault UI
    (port 8200) on each supplied hostname.

    Pick hostnames from the Recon Open Ports slicer where 8500 or 8200
    shows open, or pick all hostnames when the target is a cloud-native
    or microservices environment. The wrapper scope-filters the list.
    """
    return list(check_consul_vault_ports(hostnames))


class _ConsulVaultPathArgs(BaseModel):
    """Explicit args_schema for the Consul/Vault Path Check tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Endpoint objects. Probes /consul/ui and /vault/ui on each"
            " origin (the tool deduplicates by origin). Fire when the"
            " target reverse-proxies service-discovery UIs behind a"
            " normal HTTP endpoint. The wrapper's scope filter drops"
            " endpoints whose host is outside the selected programme's"
            " structured scope."
        ),
    )


@cyber_tool("Consul/Vault Path Check", args_schema=_ConsulVaultPathArgs)
def consul_vault_path_check_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Check for HashiCorp Consul / Vault reverse-proxied at /consul/ui or
    /vault/ui on each supplied origin.

    Pick a representative set of live endpoints from Recon Endpoints; the
    tool deduplicates by origin. Use when the target reverse-proxies its
    service-discovery UIs behind a normal HTTP endpoint.
    """
    return list(check_consul_vault_paths(_parse_endpoints(endpoints)))
