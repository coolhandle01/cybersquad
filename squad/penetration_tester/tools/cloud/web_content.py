"""
Web-content exposure probes - HTTP path checks against agent-picked
endpoints. ``Sensitive Files Check`` looks for env / config / backups
/ VCS metadata / build artefacts served unintentionally;
``Admin Panels Check`` looks for admin-panel login pages at predictable
paths. Both take ``list[Endpoint]``; the wrapper-level scope filter
drops endpoints whose host is outside the selected programme's
structured scope before the probe fires.
"""

from pydantic import BaseModel, Field

from models import Endpoint, RawFinding
from squad import cyber_tool
from squad.penetration_tester.tools._decorator import _parse_endpoints
from tools.cloud import check_admin_panels, check_sensitive_files
from tools.recon.scope import TargetEndpoints


class _SensitiveFilesArgs(BaseModel):
    """Explicit args_schema for the Sensitive Files Check tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Endpoint objects. Pass a representative set of live"
            " endpoints; the tool deduplicates by origin so many can be"
            " passed without redundant probes. High-value finds on any"
            " target (.git/HEAD, .env, phpinfo.php, Apache server-status,"
            " .DS_Store) - run broadly. The wrapper's scope filter drops"
            " endpoints whose host is outside the selected programme's"
            " structured scope."
        ),
    )


@cyber_tool("Sensitive Files Check", args_schema=_SensitiveFilesArgs)
def sensitive_files_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Probe for exposed .git/HEAD, .env, phpinfo.php, Apache server-status,
    and .DS_Store files. Run broadly - these are high-value finds on any
    target.

    Pass a representative set of live endpoints; the tool deduplicates
    by origin so you can pass many without redundant probes. The
    wrapper scope-filters the list.
    """
    return list(check_sensitive_files(_parse_endpoints(endpoints)))


class _AdminPanelsArgs(BaseModel):
    """Explicit args_schema for the Admin Panels Check tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Endpoint objects. The tool deduplicates by origin so passing"
            " many is safe. Probes common admin paths (/admin, /wp-admin,"
            " /phpmyadmin, /adminer, /manager/html, /_admin) - run"
            " broadly on all live endpoints. The wrapper's scope filter"
            " drops endpoints whose host is outside the selected"
            " programme's structured scope."
        ),
    )


@cyber_tool("Admin Panels Check", args_schema=_AdminPanelsArgs)
def admin_panels_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Probe common admin panel paths: /admin, /wp-admin, /phpmyadmin,
    /adminer, /manager/html, /_admin. Run broadly on all live endpoints.

    Pass a representative set of live endpoints; the tool deduplicates
    by origin. The wrapper scope-filters the list.
    """
    return list(check_admin_panels(_parse_endpoints(endpoints)))
