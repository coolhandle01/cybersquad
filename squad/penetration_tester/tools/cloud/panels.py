"""
Hosting control-panel exposure probes - cPanel/WHM, Plesk,
DirectAdmin, Webmin. Each takes typed ``list[FQDN]`` picked by the
agent from recon (the host:port pairs the nmap pass surfaced) and a
wrapper-level ``scope_filter`` drops anything outside the selected
programme's structured scope before the probe fires. A confirmed
exposed admin panel is a credentialled-attack target rather than a
direct vulnerability.
"""

from pydantic import BaseModel, Field

from models import FQDN, RawFinding
from squad import cyber_tool
from tools.cloud import check_cpanel, check_directadmin, check_plesk, check_webmin
from tools.recon.scope import TargetFQDNs


class _CpanelArgs(BaseModel):
    """Explicit args_schema for the cPanel/WHM Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs showing one of ports 2082, 2083, 2086, or 2087"
            " open, or hostnames on a target that appears to be a shared /"
            " managed hosting environment. Probes cPanel (2082/2083) and"
            " WHM (2086/2087) on each. The wrapper's scope filter drops"
            " out-of-scope hostnames before any probe."
        ),
    )


@cyber_tool("cPanel/WHM Check", args_schema=_CpanelArgs)
def cpanel_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check for an exposed cPanel hosting control panel (ports 2082/2083)
    and WHM (WebHost Manager) panel (ports 2086/2087) on each supplied
    hostname.

    Pick hostnames from the Recon Open Ports slicer where one of 2082,
    2083, 2086, or 2087 shows open, or pick all hostnames when the target
    is a shared / managed hosting environment. The wrapper scope-filters
    the list.
    """
    return list(check_cpanel(hostnames))


class _PleskArgs(BaseModel):
    """Explicit args_schema for the Plesk Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs showing port 8880 or 8443 open, or hostnames on a"
            " managed-hosting or VPS provider. Probes Plesk on 8880 (HTTP)"
            " and 8443 (HTTPS). The wrapper's scope filter drops"
            " out-of-scope hostnames before any probe."
        ),
    )


@cyber_tool("Plesk Check", args_schema=_PleskArgs)
def plesk_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check for an exposed Plesk web hosting control panel on ports 8880
    (HTTP) and 8443 (HTTPS) on each supplied hostname.

    Pick hostnames from the Recon Open Ports slicer where 8880 or 8443
    shows open, or pick all hostnames when the target is a managed
    hosting or VPS provider. The wrapper scope-filters the list.
    """
    return list(check_plesk(hostnames))


class _DirectadminArgs(BaseModel):
    """Explicit args_schema for the DirectAdmin Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs showing port 2222 open on a target that appears to"
            " be shared hosting. The wrapper's scope filter drops"
            " out-of-scope hostnames before any probe."
        ),
    )


@cyber_tool("DirectAdmin Check", args_schema=_DirectadminArgs)
def directadmin_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check for an exposed DirectAdmin hosting control panel on port 2222
    on each supplied hostname.

    Pick hostnames from the Recon Open Ports slicer where 2222 shows
    open on a shared-hosting target. The wrapper scope-filters the list.
    """
    return list(check_directadmin(hostnames))


class _WebminArgs(BaseModel):
    """Explicit args_schema for the Webmin Check tool."""

    hostnames: TargetFQDNs = Field(
        description=(
            "FQDNs showing port 10000 open, or hostnames on a"
            " self-hosted Linux server. The wrapper's scope filter drops"
            " out-of-scope hostnames before any probe."
        ),
    )


@cyber_tool("Webmin Check", args_schema=_WebminArgs)
def webmin_tool(hostnames: list[FQDN]) -> list[RawFinding]:
    """
    Check for an exposed Webmin Linux server administration panel on port
    10000 on each supplied hostname.

    Pick hostnames from the Recon Open Ports slicer where 10000 shows
    open, or pick all hostnames when the target is a self-hosted Linux
    server. The wrapper scope-filters the list.
    """
    return list(check_webmin(hostnames))
