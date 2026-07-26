"""
Server-side injection probes - payloads that are executed or parsed
on the server (database, OS shell, XML parser, template engine, LDAP
directory, JS prototype chain, LLM system prompt).

Variant-based StrEnum-driven probes per the cybersquad-pentest-tool
skill - the agent picks a targeted subset of payload strategies rather
than running everything or nothing.
"""

from pydantic import BaseModel, Field

from models import Endpoint, RawFinding
from squad.penetration_tester.tools._decorator import _parse_endpoints, pentest_tool
from tools.pentest.cmd_injection import CmdPayload, check_cmd_injection
from tools.pentest.ldap_injection import LdapPayload, check_ldap_injection
from tools.pentest.nosqli import run_nosqli
from tools.pentest.prompt_injection import PromptPayload, check_prompt_injection
from tools.pentest.prototype_pollution import (
    PrototypePollutionPayload,
    check_prototype_pollution,
)
from tools.pentest.sqlmap import run_sqlmap
from tools.pentest.ssti import SstiPayload, check_ssti
from tools.pentest.xxe import XxePayload, check_xxe
from tools.recon.scope import TargetEndpoints


class _SqlmapArgs(BaseModel):
    """Explicit args_schema for the SQLMap Injection Scan tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Parameterised endpoint objects to test for SQL injection. Pass"
            " only endpoints whose ``parameters`` is non-empty AND where"
            " injection is plausible (SQL errors observed, numeric/string"
            " parameters in URLs or forms). Do not pass all endpoints"
            " blindly - sqlmap is slow and loud."
        ),
    )


@pentest_tool("SQLMap Injection Scan", check_fn=run_sqlmap, args_schema=_SqlmapArgs)
def sqlmap_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Run sqlmap against specific parameterised endpoints.

    endpoints: list of endpoint objects that have parameters you want
      to test for SQL injection. Only pass endpoints where parameters is non-empty
      and where there is reason to suspect injection (e.g. error disclosure findings
      showing SQL errors, numeric/string parameters in URLs or forms).
      Example: [{"url": "https://example.com/search", "parameters": ["q", "page"]}]

    Do not pass all endpoints blindly - sqlmap is slow and loud. Pass only the
    endpoints where injection is plausible based on the recon context.

    """
    return list(run_sqlmap(_parse_endpoints(endpoints)))


class _SstiArgs(BaseModel):
    """Explicit args_schema for the Server-Side Template Injection Probe tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Parameterised endpoint objects. Prioritise endpoints where the"
            " parameter is rendered into HTML the response returns (search,"
            " comment, preview, name, template parameters) and where the"
            " stack is template-heavy (Flask/Jinja2, Django, Symfony/Twig,"
            " Rails/ERB, Spring/FreeMarker)."
        ),
    )
    payloads: list[SstiPayload] | None = Field(
        default=None,
        description=(
            "Optional list of template-engine variants to try; omit or pass"
            " null to try all. When the engine is known from recon, pass"
            " only the matching engine (e.g. ['jinja2'] for a Flask target)."
        ),
    )


@pentest_tool(
    "Server-Side Template Injection Probe",
    check_fn=check_ssti,
    args_schema=_SstiArgs,
)
def ssti_probe_tool(
    endpoints: list[Endpoint],
    payloads: list[SstiPayload] | None = None,
) -> list[RawFinding]:
    """
    Inject template-language expressions (Jinja2/Twig/Liquid, Mako/FreeMarker,
    ERB/EJS, Ruby interpolation) into URL parameters and look for the evaluated
    arithmetic product in the response body. Confirmation requires the product
    to appear AND the literal expression to be absent, which rules out the
    common false positive of an app that just echoes the raw input.

    endpoints: list of endpoint objects. Prioritise endpoints where
      any of the following apply:
      - Parameter values are rendered into HTML the response returns (search,
        comment, preview, name, template parameters)
      - Technologies mention a template-heavy stack (Flask/Jinja2, Django,
        Symfony/Twig, Rails/ERB, Spring with FreeMarker, etc.)
      - Error disclosure findings mention template internals
      Example: [{"url": "https://example.com/preview", "parameters": ["name"]}]

    payloads: optional list of engine variants to try; omit or pass null to
      try all. When the template engine is known from recon, pass only the
      matching engine (e.g. just "jinja2" for a Flask target).

    SSTI confirmed at the canary-arithmetic level is HIGH; the VR should
    escalate to CRITICAL when manual follow-up demonstrates RCE primitives
    (sandbox escape, attribute traversal, OS command execution).

    """
    return list(check_ssti(_parse_endpoints(endpoints), payloads))


class _PromptInjectionArgs(BaseModel):
    """Explicit args_schema for the Prompt Injection Probe tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "LLM-backed endpoint objects. Pass endpoints where the OSINT"
            " Analyst's LLM Endpoint Detection tool returned results,"
            " technologies include 'LLM', or paths suggest an AI assistant"
            " (/chat, /ask, /ai, /assistant, /copilot)."
        ),
    )
    payloads: list[PromptPayload] | None = Field(
        default=None,
        description=(
            "Optional list of injection-technique variants to try; omit or"
            " pass null to try all. Use ['override'] for direct instruction"
            " override, ['conversation'] for transcript-style, ['token-"
            "boundary'] for models that recognise chat delimiter tokens."
        ),
    )


@pentest_tool(
    "Prompt Injection Probe",
    check_fn=check_prompt_injection,
    args_schema=_PromptInjectionArgs,
)
def prompt_injection_tool(
    endpoints: list[Endpoint],
    payloads: list[PromptPayload] | None = None,
) -> list[RawFinding]:
    """
    Probe LLM-backed endpoints for prompt injection by injecting a canary string
    in multiple request formats (OpenAI chat, generic message, prompt completion).

    endpoints: list of endpoint objects. Use this tool when:
      - The OSINT Analyst's LLM Endpoint Detection tool returned results
      - Endpoint technologies include 'LLM'
      - URL paths suggest an AI assistant (/chat, /ask, /ai, /assistant, /copilot)
      - The target is known to use an AI product or chatbot feature

    payloads: optional list of injection technique variants to try; omit or
      pass null to try all. Use "override" for direct instruction override,
      "conversation" for transcript-style injection, "token-boundary" for
      models that recognise chat delimiter tokens.

    Severity:
      - Canary reflected in response (direct injection): CRITICAL
      - Response contains system prompt shaped text (leakage): HIGH


    """
    return list(check_prompt_injection(_parse_endpoints(endpoints), payloads))


class _NosqliArgs(BaseModel):
    """Explicit args_schema for the NoSQL Injection Scan tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Parameterised endpoint objects. Prioritise endpoints where"
            " technologies mention MongoDB / DocumentDB / Mongoose, parameters"
            " include id / user / username / filter / query, error disclosure"
            " findings mention BSON / ObjectId, or the endpoint is an auth"
            " route (login, signup, profile) with parameter-bearing URLs."
        ),
    )


@pentest_tool("NoSQL Injection Scan", check_fn=run_nosqli, args_schema=_NosqliArgs)
def nosqli_tool(endpoints: list[Endpoint]) -> list[RawFinding]:
    """
    Run nosqli against parameterised endpoints to detect NoSQL injection vulnerabilities.

    endpoints: list of endpoint objects. Prioritise endpoints that have
      parameters AND where any of the following apply:
      - Technologies mention MongoDB, DocumentDB, Mongoose, or similar document stores
      - Parameters include id, user, username, filter, query, or similar lookup keys
      - Error disclosure findings mention BSON, ObjectId, or a MongoDB driver
      - Auth routes (login, signup, profile) with parameter-bearing URLs
      Example: [{"url": "https://example.com/api/login", "parameters": ["username", "password"]}]


    """
    return list(run_nosqli(_parse_endpoints(endpoints)))


class _LdapInjectionArgs(BaseModel):
    """Explicit args_schema for the LDAP Injection Probe tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Parameterised endpoint objects. Prioritise endpoints whose"
            " parameter names suggest authentication or directory lookup"
            " (username, user, login, email, uid, cn, search, filter, q),"
            " paths suggest auth / directory (/login, /auth, /search,"
            " /directory, /ldap, /user), or technologies mention LDAP /"
            " Active Directory / OpenLDAP / JNDI."
        ),
    )
    payloads: list[LdapPayload] | None = Field(
        default=None,
        description=(
            "Optional list of LDAP injection variants to try; omit or pass"
            " null to try all. Use ['auth-bypass'] first on a /login"
            " endpoint to confirm the class with a single request, then"
            " escalate."
        ),
    )


@pentest_tool(
    "LDAP Injection Probe",
    check_fn=check_ldap_injection,
    args_schema=_LdapInjectionArgs,
)
def ldap_injection_tool(
    endpoints: list[Endpoint],
    payloads: list[LdapPayload] | None = None,
) -> list[RawFinding]:
    """
    Inject LDAP bypass and enumeration payloads into URL parameters to detect
    LDAP injection vulnerabilities against Active Directory or OpenLDAP backends.

    endpoints: list of endpoint objects. Prioritise endpoints that have
      parameters AND where any of the following apply:
      - Parameter names suggest authentication or directory lookup (username, user,
        login, email, uid, cn, search, filter, q)
      - URL path suggests auth or directory (/login, /auth, /search, /directory,
        /ldap, /user)
      - Technologies mention LDAP, Active Directory, OpenLDAP, or JNDI
      Example: [{"url": "https://example.com/login", "parameters": ["username"]}]

    payloads: optional list of injection variants to try; omit or pass null
      to try all. Use "auth-bypass" first on a /login endpoint to confirm the
      class with a single request, then escalate.

    Detection tiers:
      HIGH   - status code change vs baseline suggests auth bypass
      MEDIUM - LDAP/AD error strings in response body (confirms LDAP backend)
      MEDIUM - server error (500) only on LDAP payload, not on baseline


    """
    return list(check_ldap_injection(_parse_endpoints(endpoints), payloads))


class _CmdInjectionArgs(BaseModel):
    """Explicit args_schema for the Command Injection Probe tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Parameterised endpoint objects. Prioritise endpoints whose"
            " parameter names suggest shell / system interaction (cmd, exec,"
            " command, shell, run, ping, host, ip, addr, query, search,"
            " name, input), technologies mention CGI / Perl / PHP, paths"
            " suggest system utilities (/ping, /traceroute, /lookup, /exec,"
            " /run, /convert, /render, /preview, /generate), or error"
            " disclosure findings mention exec / popen / system / shell."
        ),
    )
    payloads: list[CmdPayload] | None = Field(
        default=None,
        description=(
            "Optional list of shell-separator variants to try; omit or pass"
            " null to try all. When the OS is known, pass only matching"
            " separators (e.g. ['windows-amp'] for an IIS target;"
            " ['semicolon', 'dollar-paren'] for a known Unix target)."
        ),
    )


@pentest_tool(
    "Command Injection Probe",
    check_fn=check_cmd_injection,
    args_schema=_CmdInjectionArgs,
)
def cmd_injection_tool(
    endpoints: list[Endpoint],
    payloads: list[CmdPayload] | None = None,
) -> list[RawFinding]:
    """
    Append OS command payloads to URL parameter values using common shell
    separators and look for a canary string echoed back in the response body.
    Confirmed echo is CRITICAL - it is direct proof of arbitrary command execution.

    endpoints: list of endpoint objects. Prioritise endpoints that have
      parameters AND where any of the following apply:
      - Parameter names suggest shell or system interaction (cmd, exec, command,
        shell, run, ping, host, ip, addr, query, search, name, input)
      - Technologies mention CGI, Perl, PHP, or shell-invoking frameworks
      - URL paths suggest system utilities (/ping, /traceroute, /lookup, /exec,
        /run, /convert, /render, /preview, /generate)
      - Error disclosure findings mention exec, popen, system, or shell functions
      Example: [{"url": "https://example.com/ping", "parameters": ["host"]}]

    payloads: optional list of separator variants to try; omit or pass null
      to try all. When the OS is known, pass only matching separators
      (e.g. just "windows-amp" for an IIS target; "semicolon" and
      "dollar-paren" for a known Unix target).

    Detection is in-band only. If no finding is returned on a suspicious endpoint,
    escalate to manual time-based testing (e.g. sleep 5 with response-time delta).

    """
    return list(check_cmd_injection(_parse_endpoints(endpoints), payloads))


class _XxeArgs(BaseModel):
    """Explicit args_schema for the XXE Probe tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Endpoint objects. Prioritise endpoints whose technologies mention"
            " SOAP / XML-RPC / WSDL / XML / web services, paths contain"
            " /soap /xml /wsdl /rpc /service /api or end in .asmx / .wsdl /"
            " .xml, OSINT noted XML or SOAP in the response, or the endpoint"
            " accepts file uploads."
        ),
    )
    payloads: list[XxePayload] | None = Field(
        default=None,
        description=(
            "Optional list of probe variants to try; omit or pass null to"
            " try all. linux-* probes target /etc/passwd, windows-* probes"
            " target win.ini, error-* probes are MEDIUM-severity backend"
            " confirmation only. Select error-* alone for a quiet 'is there"
            " an XML parser?' reconnaissance pass."
        ),
    )


@pentest_tool("XXE Probe", check_fn=check_xxe, args_schema=_XxeArgs)
def xxe_probe_tool(
    endpoints: list[Endpoint],
    payloads: list[XxePayload] | None = None,
) -> list[RawFinding]:
    """
    POST crafted XML bodies to endpoints to detect XML External Entity (XXE)
    injection vulnerabilities.

    endpoints: list of endpoint objects. Prioritise endpoints where
      any of the following apply:
      - technologies mention SOAP, XML-RPC, WSDL, XML, or web services
      - URL path contains /soap, /xml, /wsdl, /rpc, /service, /api, or ends
        in .asmx, .wsdl, .xml
      - The OSINT Analyst noted XML or SOAP in the response body or headers
      - The endpoint accepts file uploads (multipart may include XML processing)
      Example: [{"url": "https://example.com/soap/service", "status_code": 200}]

    payloads: optional list of probe variants to try; omit or pass null to
      try all. linux-* probes target /etc/passwd, windows-* probes target
      win.ini. The error-* probes are MEDIUM-severity backend confirmation
      and only run if no file-read probe fires - select them alone for a
      quiet "is there an XML parser?" reconnaissance pass.

    Detection tiers:
      CRITICAL - file marker from /etc/passwd or Windows win.ini appears in
                 the response body (confirmed in-band file read via entity expansion)
      MEDIUM   - XML parser error strings in the response body (confirms XML
                 parsing backend; warrants manual OOB/blind XXE follow-up)

    Both generic XML and SOAP-envelope wrappers are tried automatically.

    """
    return list(check_xxe(_parse_endpoints(endpoints), payloads))


class _PrototypePollutionArgs(BaseModel):
    """Explicit args_schema for the Prototype Pollution Check tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Endpoint objects. Prioritise endpoints whose technologies mention"
            " Node.js / Express / Koa / Hapi / Fastify or other JS / TS"
            " server frameworks, the API accepts JSON request bodies, URL"
            " parameters are parsed server-side into plain objects (lodash"
            " merge, recursive assign), or the target is a REST / GraphQL"
            " API with a JavaScript backend."
        ),
    )
    payloads: list[PrototypePollutionPayload] | None = Field(
        default=None,
        description=(
            "Optional list of injection variants to try; omit or pass null"
            " to try all. proto-* / constructor-* target URL query-string"
            " vectors, json-* target JSON POST body vectors. Pass json-*"
            " alone for a JSON-only API or proto-* alone for a quick"
            " reconnaissance pass."
        ),
    )


@pentest_tool(
    "Prototype Pollution Check",
    check_fn=check_prototype_pollution,
    args_schema=_PrototypePollutionArgs,
)
def prototype_pollution_tool(
    endpoints: list[Endpoint],
    payloads: list[PrototypePollutionPayload] | None = None,
) -> list[RawFinding]:
    """
    Probe endpoints for prototype pollution by injecting __proto__ and
    constructor.prototype payloads via URL query strings and JSON POST bodies,
    then checking whether a canary property is reflected in the response or
    whether the server returns an unhandled error.

    endpoints: list of endpoint objects. Use this tool when:
      - Technologies mention Node.js, Express, Koa, Hapi, Fastify, or other
        JavaScript/TypeScript server frameworks
      - The API accepts JSON request bodies (Content-Type: application/json)
      - URL parameters are parsed server-side into plain objects (lodash merge,
        recursive assign, query-string to object conversions)
      - The target is a REST or GraphQL API with a JavaScript backend
      Example: [{"url": "https://api.example.com/users", "status_code": 200}]

    payloads: optional list of injection variants to try; omit or pass null
      to try all. The proto-* and constructor-* names are URL query-string
      vectors; the json-* names are JSON POST body vectors. Select just the
      json-* set for a JSON-only API, or just the proto-* set for a quick
      reconnaissance pass.

    Detection tiers:
      CRITICAL - the canary string appears in the response body after injection,
                 confirming the polluted property is accessible to application code.
      MEDIUM   - the server returns HTTP 500 only after an injection attempt,
                 suggesting the injection triggered an unhandled error during
                 prototype chain traversal (warrants manual follow-up).

    One finding per endpoint. CRITICAL takes priority over MEDIUM.

    """
    return list(check_prototype_pollution(_parse_endpoints(endpoints), payloads))
