"""
External-scanner wrappers - probes that delegate to a binary
(``nuclei``) rather than implementing the probe logic inline.

One wrapper today; lives in its own module so the per-family taxonomy
stays consistent and a second external runner does not have to bend
either ``injection.py`` or ``disclosure.py`` to fit.
"""

from pydantic import BaseModel, Field

from models import Endpoint, RawFinding
from squad.penetration_tester.tools._decorator import _parse_endpoints, pentest_tool
from tools.pentest.nuclei import run_nuclei
from tools.recon.scope import TargetEndpoints


class _NucleiScanArgs(BaseModel):
    """Explicit args_schema for the Nuclei Scan tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Live endpoint objects to scan (status_code < 500). Pass the typed"
            " list directly from recon; do not stringify."
        ),
    )
    tech_tags: list[str] | None = Field(
        default=None,
        description=(
            "Optional nuclei template tags to focus on, mapped from detected"
            " technologies (e.g. ['wordpress', 'cve']). Omit or pass null to"
            " run all templates. Common tags: wordpress, drupal, joomla,"
            " apache, nginx, iis, spring, laravel, django, rails, php, cve,"
            " exposure, misconfig."
        ),
    )


@pentest_tool("Nuclei Scan", check_fn=run_nuclei, args_schema=_NucleiScanArgs)
def nuclei_scan_tool(
    endpoints: list[Endpoint], tech_tags: list[str] | None = None
) -> list[RawFinding]:
    """
    Run nuclei against a specific set of endpoints, optionally filtered by template tags.

    endpoints: list of endpoint objects to scan. Extract from AttackGraph:
      select live endpoints (status_code < 500), use the typed list directly.
      Example: [{"url": "https://example.com/", "status_code": 200, "technologies": ["WordPress"]}]

    tech_tags: optional list of nuclei template tags to focus on. Map from detected
      technologies: WordPress -> ["wordpress"], Apache -> ["apache"], Spring -> ["spring"].
      Common tags: wordpress, drupal, joomla, apache, nginx, iis, spring, laravel,
      django, rails, php, cve, exposure, misconfig. Omit or pass an empty list to run all templates.
      Example: ["wordpress", "cve"]

    Prefer narrow tag lists when you have technology intel - running all templates
    against every endpoint is slow and noisy.

    """
    return list(run_nuclei(_parse_endpoints(endpoints), tech_tags=tech_tags or None))
