"""
Access-control probes - IDOR (boundary / parameter / path-segment
attacks against authorisation checks) and JWT (algorithm
confusion, signature stripping, expiry tampering).
"""

from pydantic import BaseModel, Field

from models import Endpoint, RawFinding
from squad.penetration_tester.tools._decorator import _parse_endpoints, pentest_tool
from tools.pentest.idor import IDORAttack, check_idor
from tools.pentest.jwt import JwtAttack, check_jwt
from tools.recon.scope import TargetEndpoint, TargetEndpoints


class _IdorArgs(BaseModel):
    """Explicit args_schema for the IDOR Probe tool."""

    endpoints: TargetEndpoints = Field(
        description=(
            "Endpoint objects. Prioritise endpoints whose URL path includes"
            " numeric segments (/api/users/42, /orders/9), parameters include"
            " id / user_id / account_id / order_id, or the endpoint handles"
            " authenticated or per-user data."
        ),
    )
    attacks: list[IDORAttack] | None = Field(
        default=None,
        description=(
            "Optional list of IDOR attack strategies to run; omit or pass"
            " null to run all three. Use ['boundary'] for a quiet recon pass"
            " (2 requests per candidate), ['sequential'] when an ID is"
            " already known and adjacent objects are suspected, or all three"
            " for maximum coverage."
        ),
    )


@pentest_tool("IDOR Probe", check_fn=check_idor, args_schema=_IdorArgs)
def idor_probe_tool(
    endpoints: list[Endpoint],
    attacks: list[IDORAttack] | None = None,
) -> list[RawFinding]:
    """
    Probe ID-shaped URL path segments and parameters for Insecure Direct
    Object Reference (IDOR) - the most-rewarded class on HackerOne (OWASP A01).

    Numeric path segments (e.g. /users/12345) and ID-shaped parameters (id,
    user_id, account_id, order_id, ...) are probed using the selected attack
    strategies (omit or pass null to run all three):

      sequential    - neighbour IDs: value-1, value+1, value-100 (numeric path
                      segments where the current value is visible in the URL).
                      For query parameters where no current value is known,
                      probes 1 and 2 instead.
      boundary      - 0 and -1; catches missing lower-bound checks.
      type-juggling - 1.0, 1e1, 01; targets backends that accept loose numeric
                      input and may bypass strict access-control comparisons.

    Detection signals:
      HIGH   - status changes from 401/403 to 200 (access-control bypass)
      HIGH   - 200 response body contains a PII pattern (email, sensitive key)
      MEDIUM - unexpected 200 for boundary ID (id=0 or id=-1)

    endpoints: list of endpoint objects. Prioritise endpoints where:
      - The URL path includes numeric segments (/api/users/42, /orders/9)
      - Parameters include id, user_id, account_id, order_id, or similar
      - The endpoint handles authenticated or per-user data
      Example: [{"url": "https://example.com/api/users/42", "status_code": 200}]

    Use attacks=["boundary"] for a quiet reconnaissance pass (2 requests per
    candidate). Use attacks=["sequential"] when you already know an ID and want
    to probe adjacent objects. Use all three (default) for maximum coverage.

    One finding per endpoint; stops after the first confirming probe. Does not
    brute-force ID ranges.
    """
    return list(check_idor(_parse_endpoints(endpoints), attacks))


class _JwtCheckArgs(BaseModel):
    """Explicit args_schema for the JWT Vulnerability Check tool."""

    token: str = Field(
        description=(
            "Raw JWT string (three base64url parts separated by dots)."
            " Source from Authorization: Bearer headers, Set-Cookie session"
            " / auth cookies, JS source or API responses with access_token /"
            " id_token fields, or any cookie value beginning with 'eyJ'"
            " (base64url-encoded JSON header)."
        ),
    )
    endpoint: TargetEndpoint = Field(
        description=(
            "Endpoint that validates the JWT - one that returns 401 / 403"
            " without a valid token and 200 on success. Use the endpoint"
            " where the token was first observed (Authorization header"
            " on /api/profile, /api/me, /dashboard, etc.). Pass the full"
            " Endpoint shape from recon (``Recon Endpoints``); the URL"
            " has to parse as HTTP/S."
        ),
    )
    attacks: list[JwtAttack] | None = Field(
        default=None,
        description=(
            "Optional list of attack classes to run; omit or pass null to"
            " run all seven. Useful when chaining - e.g. ['alg-none',"
            " 'claims-escalation'] to confirm missing signature verification"
            " without firing every kid variant against an endpoint where"
            " kid is not even in the header."
        ),
    )


@pentest_tool(
    "JWT Vulnerability Check",
    check_fn=check_jwt,
    args_schema=_JwtCheckArgs,
)
def jwt_check_tool(
    token: str,
    endpoint: Endpoint,
    attacks: list[JwtAttack] | None = None,
) -> list[RawFinding]:
    """
    Test a JWT token for common vulnerabilities by replaying forged tokens
    against the authenticated endpoint and detecting 4xx -> 2xx transitions.

    token: the raw JWT string (three base64url parts separated by dots).
      Source from: Authorization: Bearer headers in observed requests,
      Set-Cookie headers with session/auth cookies, JS source or API responses
      containing access_token or id_token fields, cookie values that begin with
      eyJ (base64url-encoded JSON header).

    endpoint: the URL that validates the JWT. Should return 401 or 403 without
      a valid token and 200 on success. Use the endpoint where the token was
      first observed in use (e.g. /api/profile, /api/me, /dashboard).

    attacks: optional list of attack classes to run; omit or pass null to run
      all seven. Useful when chaining - e.g. ["alg-none", "claims-escalation"]
      to confirm a missing-signature-verification class without firing every
      kid variant against an endpoint where kid is not even in the header.

    Attacks attempted (when not filtered): alg:none (4 variants), RS256->HS256
    confusion via JWKS, weak HMAC secret brute-force, kid path traversal,
    kid SQL injection, kid NoSQL injection (MongoDB operators), and claims
    tampering without re-signing.

    Run on every JWT discovered during recon, especially on admin and account
    endpoints. All confirmed bypasses are CRITICAL.

    """
    # ``check_jwt`` takes the validating URL as a string. The args_schema
    # accepts a typed ``Endpoint`` so the agent passes the recon shape and
    # CrewAI validates URL well-formedness upstream; extract ``.url`` via
    # the both-shapes adapter so test invocations passing a dict and the
    # LLM path passing a dict both resolve to the URL.
    return list(check_jwt(token, Endpoint.model_validate(endpoint).url, attacks))
