"""HackerOne hacker-API response fixtures.

Builder functions returning the JSON:API payloads HackerOne's hacker API
actually returns, transcribed key-for-key from the official docs
(api.hackerone.com/hacker-resources) - the same source the repo's H1 cheatsheet
was copied from. Tests build doubles from these so a test payload cannot drift
away from the real contract the way hand-faked dicts did: a phantom bounty_table
on the detail endpoint, an un-paginated single scope page, a missing
scope_exclusions endpoint.

Faithful points the old hand-rolled fakes got wrong, pinned here once:
  - the programme DETAIL endpoint exposes NO bounty_table and NO payout/response
    stats - those keys are simply not in the documented attribute set;
  - detail wraps its resource in {"data": {...}} (the same envelope as the list);
  - structured_scopes and scope_exclusions are paginated (links.next).

Plain functions (imported directly), matching the sibling tests/fixtures/*.py
builder modules. ``next_link`` takes the absolute URL H1 puts in links.next:
callers pass one built from the client base when exercising pagination, and omit
it (the default) for a single terminal page. Any attribute can be overridden via
keyword to assert on a specific value or, by passing it absent, to exercise a
parser default.
"""

from __future__ import annotations


def _page(items: list[dict], next_link: str | None) -> dict:
    return {"data": items, "links": {"next": next_link} if next_link else {}}


def programme_attributes(handle: str = "acme", **overrides: object) -> dict:
    """The attribute block of a programme resource - the documented hacker-API
    field set, verbatim. Note the absence of bounty_table and of any payout or
    response-time stats: the hacker API does not expose them here."""
    attributes: dict[str, object] = {
        "handle": handle,
        "name": handle,
        "currency": "usd",
        "policy": f"{handle}'s program policy.",
        "profile_picture": "/assets/global-elements/add-team.png",
        "submission_state": "open",
        "triage_active": None,
        "state": "public_mode",
        "started_accepting_at": None,
        "number_of_reports_for_user": 0,
        "number_of_valid_reports_for_user": 0,
        "bounty_earned_for_user": 0,
        "last_invitation_accepted_at_for_user": None,
        "bookmarked": False,
        "allows_bounty_splitting": False,
        "offers_bounties": True,
        "open_scope": True,
        "fast_payments": True,
        "gold_standard_safe_harbor": False,
    }
    attributes.update(overrides)
    return attributes


def programme_resource(handle: str = "acme", **overrides: object) -> dict:
    """One programme resource object: {id, type, attributes, relationships}."""
    return {
        "id": 9,
        "type": "program",
        "attributes": programme_attributes(handle, **overrides),
        "relationships": {"structured_scopes": {"data": []}},
    }


def programme_detail(handle: str = "acme", **overrides: object) -> dict:
    """GET /hackers/programs/{handle} - the wrapped detail response."""
    return {"data": programme_resource(handle, **overrides)}


def programmes_list(
    handles: list[str] | None = None,
    *,
    items: list[dict] | None = None,
    next_link: str | None = None,
) -> dict:
    """GET /hackers/programs - {"data": [resource, ...], "links": {...}}."""
    if items is None:
        items = [programme_resource(h) for h in (handles or ["acme"])]
    return _page(items, next_link)


def structured_scope(
    asset_identifier: str = "https://api.hackerone.com",
    asset_type: str = "URL",
    *,
    eligible_for_bounty: bool = True,
    eligible_for_submission: bool = True,
    instruction: str | None = "This is our API",
    max_severity: str | None = "critical",
) -> dict:
    """One GET /hackers/programs/{handle}/structured_scopes entry."""
    return {
        "id": "1",
        "type": "structured-scope",
        "attributes": {
            "asset_type": asset_type,
            "asset_identifier": asset_identifier,
            "eligible_for_bounty": eligible_for_bounty,
            "eligible_for_submission": eligible_for_submission,
            "instruction": instruction,
            "max_severity": max_severity,
            "created_at": "2016-02-02T04:05:06.000Z",
            "updated_at": "2016-02-02T04:05:06.000Z",
            "confidentiality_requirement": "high",
            "integrity_requirement": "high",
            "availability_requirement": "high",
        },
    }


def structured_scopes(items: list[dict] | None = None, *, next_link: str | None = None) -> dict:
    """GET /hackers/programs/{handle}/structured_scopes - paginated list."""
    return _page([structured_scope()] if items is None else items, next_link)


def scope_exclusion(
    category: str = "Denial of Service",
    details: str = "No DoS/DDoS testing of any kind.",
) -> dict:
    """One GET /hackers/programs/{handle}/scope_exclusions entry."""
    return {
        "id": "123",
        "type": "scope-exclusion",
        "attributes": {
            "category": category,
            "details": details,
            "created_at": "2024-01-01T00:00:00.000Z",
            "updated_at": "2024-01-01T00:00:00.000Z",
        },
    }


def scope_exclusions(items: list[dict] | None = None, *, next_link: str | None = None) -> dict:
    """GET /hackers/programs/{handle}/scope_exclusions - paginated list."""
    return _page([scope_exclusion()] if items is None else items, next_link)
