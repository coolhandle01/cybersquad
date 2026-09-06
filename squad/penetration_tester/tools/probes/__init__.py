"""squad/penetration_tester/tools/probes - the 25 ``@pentest_tool`` probe wrappers.

Split per-family across sibling sub-modules so each file owns one
cohesive attack mechanism:

- ``external`` - external scanner wrappers (``nuclei``).
- ``injection`` - server-side injection where the payload is executed
  or parsed on the server (sqlmap, NoSQL, SSTI, LDAP, command, XXE,
  prototype pollution, prompt injection against LLM-bearing
  endpoints).
- ``headers`` - HTTP-shape / parameter-handling misconfig (cookies,
  CORS, CSRF, header injection, host header, HPP).
- ``network`` - URL / redirect abuse (SSRF, open redirect).
- ``client_side`` - reflective probes whose payload echoes back to the
  user (reflected XSS, header-driven XSS, path traversal into client-
  visible content).
- ``disclosure`` - information leakage (JS source maps, missing SRI,
  error / stack-trace disclosure).
- ``auth`` - access-control bypass (IDOR, JWT).

This module re-exports every wrapper + args_schema class so the parent
agent ``squad.penetration_tester.__init__`` keeps a single import site
(``from squad.penetration_tester.tools.probes import ...``) and the public
surface of the agent module does not change.
"""

from squad.penetration_tester.tools.probes.auth import (
    _IdorArgs,
    _JwtCheckArgs,
    idor_probe_tool,
    jwt_check_tool,
)
from squad.penetration_tester.tools.probes.client_side import (
    _HeaderXssArgs,
    _PathTraversalArgs,
    _XssArgs,
    header_xss_tool,
    path_traversal_tool,
    xss_probe_tool,
)
from squad.penetration_tester.tools.probes.disclosure import (
    _ErrorDisclosureArgs,
    _SourceMapsArgs,
    _SriCheckArgs,
    error_disclosure_tool,
    source_maps_tool,
    sri_check_tool,
)
from squad.penetration_tester.tools.probes.external import (
    _NucleiScanArgs,
    nuclei_scan_tool,
)
from squad.penetration_tester.tools.probes.headers import (
    _CookieCheckArgs,
    _CsrfCheckArgs,
    _HeaderInjectionArgs,
    _HostHeaderArgs,
    _HppArgs,
    cookie_check_tool,
    csrf_check_tool,
    header_injection_tool,
    host_header_tool,
    hpp_probe_tool,
)
from squad.penetration_tester.tools.probes.injection import (
    _CmdInjectionArgs,
    _LdapInjectionArgs,
    _NosqliArgs,
    _PromptInjectionArgs,
    _PrototypePollutionArgs,
    _SqlmapArgs,
    _SstiArgs,
    _XxeArgs,
    cmd_injection_tool,
    ldap_injection_tool,
    nosqli_tool,
    prompt_injection_tool,
    prototype_pollution_tool,
    sqlmap_tool,
    ssti_probe_tool,
    xxe_probe_tool,
)
from squad.penetration_tester.tools.probes.network import (
    _OpenRedirectArgs,
    _SsrfArgs,
    open_redirect_tool,
    ssrf_probe_tool,
)

__all__ = [  # noqa: RUF022 - grouped by probe-family sub-module, not alphabetised
    # auth
    "_IdorArgs",
    "_JwtCheckArgs",
    "idor_probe_tool",
    "jwt_check_tool",
    # client_side
    "_HeaderXssArgs",
    "_PathTraversalArgs",
    "_XssArgs",
    "header_xss_tool",
    "path_traversal_tool",
    "xss_probe_tool",
    # disclosure
    "_ErrorDisclosureArgs",
    "_SourceMapsArgs",
    "_SriCheckArgs",
    "error_disclosure_tool",
    "source_maps_tool",
    "sri_check_tool",
    # external
    "_NucleiScanArgs",
    "nuclei_scan_tool",
    # headers
    "_CookieCheckArgs",
    "_CsrfCheckArgs",
    "_HeaderInjectionArgs",
    "_HostHeaderArgs",
    "_HppArgs",
    "cookie_check_tool",
    "csrf_check_tool",
    "header_injection_tool",
    "host_header_tool",
    "hpp_probe_tool",
    # injection
    "_CmdInjectionArgs",
    "_LdapInjectionArgs",
    "_NosqliArgs",
    "_PromptInjectionArgs",
    "_PrototypePollutionArgs",
    "_SqlmapArgs",
    "_SstiArgs",
    "_XxeArgs",
    "cmd_injection_tool",
    "ldap_injection_tool",
    "nosqli_tool",
    "prompt_injection_tool",
    "prototype_pollution_tool",
    "sqlmap_tool",
    "ssti_probe_tool",
    "xxe_probe_tool",
    # network
    "_OpenRedirectArgs",
    "_SsrfArgs",
    "open_redirect_tool",
    "ssrf_probe_tool",
]
