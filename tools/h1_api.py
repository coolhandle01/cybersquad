"""
tools/h1_api.py - HackerOne API wrapper.

Uses the HACKER API (api.hackerone.com/v1/hackers/*), not the customer/company
API. The hacker API authenticates with a personal H1 API token and returns
programmes accessible to that hacker (public programmes + private invitations).
The customer API (/v1/programs) requires company admin credentials and is not
used here.

Covers everything the pipeline needs:
  - Listing & ranking programmes
  - Fetching programme policy / scope
  - Submitting reports
  - Polling submission status

H1 hacker API docs: https://api.hackerone.com/hacker-resources/
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from typing import cast

import requests
from requests.auth import HTTPBasicAuth

from config import config
from models import Severity
from models.h1 import (
    DisclosureReport,
    Programme,
    ProgrammePreview,
    ScopeItem,
    ScopeType,
    SubmissionResult,
    SubmissionStatus,
)
from tools import http

logger = logging.getLogger(__name__)

# Severity mapping - H1 uses strings, we use our enum
_H1_SEVERITY_MAP: dict[str, Severity] = {
    "none": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_H1_SCOPE_TYPE_MAP: dict[str, ScopeType] = {
    "URL": ScopeType.URL,
    "WILDCARD": ScopeType.WILDCARD,
    "IP_ADDRESS": ScopeType.IP_ADDRESS,
    "CIDR": ScopeType.CIDR,
    "SOURCE_CODE": ScopeType.SOURCE_CODE,
    "HARDWARE": ScopeType.HARDWARE,
    "DOWNLOADABLE_EXECUTABLES": ScopeType.DOWNLOADABLE_EXECUTABLES,
    "GOOGLE_PLAY_APP_ID": ScopeType.GOOGLE_PLAY_APP_ID,
    "APPLE_STORE_APP_ID": ScopeType.APPLE_STORE_APP_ID,
    "WINDOWS_APP_STORE_APP_ID": ScopeType.WINDOWS_APP_STORE_APP_ID,
    "OTHER_APK": ScopeType.OTHER_APK,
    "OTHER_IPA": ScopeType.OTHER_IPA,
    "TESTFLIGHT": ScopeType.TESTFLIGHT,
    # Legacy aliases - older H1 responses used these for the now-deprecated app categories.
    "ANDROID": ScopeType.OTHER,
    "IOS": ScopeType.OTHER,
    "OTHER": ScopeType.OTHER,
}


class H1Client:
    """
    Thin, authenticated wrapper around the HackerOne v1 hacker REST API.
    All methods raise on non-2xx responses after logging the error.

    Authenticates as a hacker (personal API token), not as a company/customer.
    All programme endpoints use the /hackers/ namespace.
    """

    def __init__(self) -> None:
        self._auth = HTTPBasicAuth(
            config.h1.api_username,
            config.h1.api_token,
        )
        self._base = config.h1.base_url
        # requests.Session is NOT thread-safe, and CrewAI dispatches tool calls
        # (e.g. several hydrate_programme calls in one agent turn) on separate
        # threads that all share this single module-level client. A shared
        # Session lets concurrent requests corrupt each other's connection
        # state - returning programme B's detail for a request made for
        # programme A. Give each thread its own Session (built lazily, identical
        # auth/headers) so calls never interleave on one connection pool.
        self._local = threading.local()

    # Internal helpers

    @property
    def _session(self) -> requests.Session:
        """Per-thread requests.Session - see __init__ for the thread-safety rationale."""
        session: requests.Session | None = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.auth = self._auth
            session.headers.update(
                {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "User-Agent": http.user_agent(),
                }
            )
            self._local.session = session
        return session

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self._base}{path}"
        resp = self._session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        return cast(dict, resp.json())

    def _next_path(self, data: dict) -> str | None:
        """Relative path for the next page, or None.

        H1's JSON:API links.next is an *absolute* URL
        (https://api.hackerone.com/v1/hackers/programs?page[number]=2...);
        strip our base off so _get's concatenation doesn't double it and 404.
        """
        nxt = data.get("links", {}).get("next")
        return nxt.removeprefix(self._base) if nxt else None

    def _get_all(self, path: str, page_size: int = 100) -> list[dict]:
        """Fetch and concatenate every page of a paginated JSON:API list.

        Follows links.next from the first page to the last and joins each page's
        ``data`` array. H1 paginates the structured_scopes and scope_exclusions
        sub-resources, so reading only page one silently truncates a large
        programme's scope - this aggregates the whole set.
        """
        items: list[dict] = []
        params: dict | None = {"page[size]": page_size}
        nxt: str | None = path
        while nxt:
            data = self._get(nxt, params)
            items.extend(data.get("data", []))
            nxt = self._next_path(data)
            params = None
        return items

    def _post(self, path: str, payload: dict) -> dict:
        url = f"{self._base}{path}"
        resp = self._session.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        return cast(dict, resp.json())

    # Programme discovery

    def list_programmes(self, page_size: int = 25) -> list[dict]:
        """
        Return raw programme data from /hackers/programs.
        Returns only programmes accessible to the authenticated hacker -
        public programmes plus any private invitations.
        Paginates until we have at least config.h1.max_programmes results.
        """
        results: list[dict] = []
        params = {"page[size]": page_size}
        path: str | None = "/hackers/programs"

        while path and len(results) < config.h1.max_programmes:
            data = self._get(path, params)
            results.extend(data.get("data", []))
            path = self._next_path(data)
            params = {}

        return results[: config.h1.max_programmes]

    def get_programme_policy(self, handle: str) -> dict:
        """Fetch full policy detail for a given programme handle."""
        return self._get(f"/hackers/programs/{handle}")

    def get_structured_scope(self, handle: str, page_size: int = 100) -> dict:
        """Fetch the full structured scope (in/out) for a programme.

        The /structured_scopes sub-resource is paginated (JSON:API links.next),
        so a programme with more entries than one page is split across pages.
        Aggregate every page so parse_programme sees the COMPLETE scope; reading
        only page one silently truncates a large programme's in/out-of-scope set,
        which the PenTester would then mistake for the whole attack surface.
        """
        return {"data": self._get_all(f"/hackers/programs/{handle}/structured_scopes", page_size)}

    def get_scope_exclusions(self, handle: str, page_size: int = 100) -> dict:
        """Fetch a programme's explicit scope exclusions (the do-not-touch set).

        GET /hackers/programs/{handle}/scope_exclusions returns custom
        out-of-scope entries - each a {category, details} pair naming an excluded
        asset class or prohibited activity, distinct from the structured_scopes
        items flagged not eligible_for_submission. Paginated like
        structured_scopes. hydrate_programme folds these into
        Programme.out_of_scope so the PenTester sees the full prohibition set.
        """
        return {"data": self._get_all(f"/hackers/programs/{handle}/scope_exclusions", page_size)}

    def get_programme_detail(self, handle: str) -> dict:
        """Fetch programme detail attributes for one handle.

        Plain GET /hackers/programs/{handle} - no `include`. The hacker API does
        NOT expose bounty amounts or programme stats here: there is no
        bounty_table, response-efficiency, time-to-bounty or total-paid field
        (confirmed against the documented /hackers/* surface). The detail carries
        the access/policy attributes plus a relationships reference for scope; the
        full scope and exclusion sets live behind the dedicated
        /structured_scopes and /scope_exclusions sub-resources, which
        hydrate_programme fetches separately.
        """
        return self._get(f"/hackers/programs/{handle}")

    def browse_programmes(
        self,
        *,
        bookmarked: bool | None = None,
        offers_bounties: bool | None = None,
        submission_state: str | None = None,
        limit: int | None = None,
        page_size: int = 25,
    ) -> list[ProgrammePreview]:
        """Paginate through accessible programmes returning lightweight previews.

        Cheap by design - one HTTP call per page, no per-programme detail fetch.
        The caller surveys the catalog, shortlists handles, then pays for
        hydration on just those candidates via hydrate_programme.

        H1's list endpoint only paginates - it does NOT filter server-side - so
        the filters (bookmarked, offers_bounties, submission_state) are applied
        here, client-side, against each preview's own fields: a preview that does
        not match every supplied filter is dropped before it is returned. Pages
        are fetched until `limit` matching previews are collected or the catalog
        is exhausted.

        limit caps the total returned previews; defaults to
        config.h1.max_programmes. page_size is the per-request page size.
        """
        cap = limit if limit is not None else config.h1.max_programmes
        # H1 ignores filter[*] query params on this endpoint, so filtering is
        # client-side: None means "no constraint"; otherwise the preview's own
        # field must equal the requested value.
        wanted: dict[str, object] = {
            "offers_bounties": offers_bounties,
            "submission_state": submission_state,
            "bookmarked": bookmarked,
        }

        previews: list[ProgrammePreview] = []
        path: str | None = "/hackers/programs"
        params: dict[str, object] = {"page[size]": page_size}
        while path and len(previews) < cap:
            data = self._get(path, params)
            for raw in data.get("data", []):
                attrs = raw.get("attributes", {}) or {}
                handle = attrs.get("handle") or raw.get("id")
                if not handle:
                    # A preview with no handle cannot be hydrated downstream;
                    # the PM has no way to act on it. Drop it rather than
                    # surface a record the agent must defensively skip.
                    continue
                if any(
                    want is not None and attrs.get(field) != want for field, want in wanted.items()
                ):
                    continue
                previews.append(
                    ProgrammePreview(
                        handle=handle,
                        name=attrs.get("name"),
                        offers_bounties=attrs.get("offers_bounties"),
                        submission_state=attrs.get("submission_state"),
                        state=attrs.get("state"),
                        bookmarked=attrs.get("bookmarked"),
                    )
                )
                if len(previews) >= cap:
                    break
            path = self._next_path(data)
            params = {}

        return previews

    def hydrate_programme(self, handle: str) -> Programme:
        """Fetch full detail for one programme and return a typed Programme.

        Three calls per programme: the detail endpoint for access/policy
        attributes, the structured_scopes sub-resource for in/out scope, and the
        scope_exclusions sub-resource for explicit prohibitions (the hacker API
        inlines none of these on detail). Use after browse_programmes to drill
        into a specific candidate the PM wants to score.
        """
        detail = self.get_programme_detail(handle)
        # The detail endpoint wraps the programme in a JSON:API {"data": {...}}
        # envelope - the same shape as the list endpoint, just a single object
        # instead of an array. (The pre-#136 find_programmes hydrated via
        # detail.get("data") on this same endpoint.) `or detail` is a defensive
        # fallback so an unexpectedly unwrapped response degrades to the clear
        # ValueError below instead of a KeyError here; it is not a claim that
        # the API ever returns the object unwrapped.
        detail_data = detail.get("data") or detail
        if not detail_data.get("attributes"):
            # No usable resource object - fail loud rather than letting
            # parse_programme fabricate an "unknown" handle the PM then caches
            # and "selects". H1 returns a 2xx with no attributes for a handle
            # the account cannot access (a guessed/wrong handle), so surface
            # what it actually returned: the agent then knows to pick a handle
            # from browse_programmes rather than invent one, and the failure is
            # debuggable from the message without a re-run.
            raise ValueError(
                f"H1 returned no usable programme detail for handle {handle!r} "
                f"(GET /hackers/programs/{handle}; response keys={list(detail.keys())}, "
                f"data={detail.get('data')!r}). Hydrate only handles that "
                f"browse_programmes actually returned; do not invent handles."
            )
        # Scopes and exclusions come from dedicated sub-resources, not from
        # detail's `included` (which the hacker API leaves empty). Both are
        # paginated and aggregated; parse_programme folds the exclusions into
        # out_of_scope.
        scope_data = self.get_structured_scope(handle)
        try:
            exclusions = self.get_scope_exclusions(handle)
        except requests.HTTPError as exc:
            # Exclusions are supplementary do-not-touch detail, not gating: never
            # let them block selecting a programme (the pipeline's first step).
            # Log loudly and proceed with the structured-scope view alone.
            logger.warning("scope_exclusions fetch failed for %s: %s", handle, exc)
            exclusions = {"data": []}
        return self.parse_programme(detail_data, scope_data, exclusions)

    # Data parsers

    def parse_programme(
        self, raw: dict, scope_data: dict, scope_exclusions: dict | None = None
    ) -> Programme:
        """Convert raw H1 API dicts into a typed Programme model.

        ``scope_data`` is the aggregated /structured_scopes payload and
        ``scope_exclusions`` the aggregated /scope_exclusions payload; the
        latter's entries are merged into ``out_of_scope`` so the prohibition set
        is complete. The hacker API exposes no bounty or stats data, so
        ``bounty_table`` and the payout/response-time fields are left at their
        model defaults - there is nothing to parse (see get_programme_detail).
        """
        attrs = raw.get("attributes", {})
        handle = attrs.get("handle", raw.get("id", "unknown"))

        in_scope: list[ScopeItem] = []
        out_of_scope: list[ScopeItem] = []
        for item in scope_data.get("data", []):
            i_attrs = item.get("attributes", {})
            max_sev_str = (i_attrs.get("max_severity") or "").lower()
            scope_item = ScopeItem(
                asset_identifier=i_attrs.get("asset_identifier", ""),
                asset_type=_H1_SCOPE_TYPE_MAP.get(
                    i_attrs.get("asset_type", "OTHER"), ScopeType.OTHER
                ),
                eligible_for_bounty=i_attrs.get("eligible_for_bounty", False),
                instruction=i_attrs.get("instruction"),
                max_severity=_H1_SEVERITY_MAP.get(max_sev_str) if max_sev_str else None,
            )
            if i_attrs.get("eligible_for_submission", True):
                in_scope.append(scope_item)
            else:
                out_of_scope.append(scope_item)

        # /scope_exclusions carries custom prohibitions ({category, details}) that
        # are not structured_scopes entries - fold each into out_of_scope so the
        # PenTester sees the full do-not-touch set. category names the excluded
        # class/activity (it has no asset_identifier of its own); details is the
        # human instruction; an exclusion is never bounty-eligible.
        for excl in (scope_exclusions or {}).get("data", []):
            e_attrs = excl.get("attributes", {})
            out_of_scope.append(
                ScopeItem(
                    asset_identifier=e_attrs.get("category") or "",
                    asset_type=ScopeType.OTHER,
                    eligible_for_bounty=False,
                    instruction=e_attrs.get("details"),
                )
            )

        submission_state: str = attrs.get("submission_state", "open") or "open"
        # bounty_table and the payout/response-time stats stay at their model
        # defaults ({} / None): the hacker API does not return them (confirmed
        # against the docs, the captured detail shape, and a real run), so faking
        # them from absent attributes is exactly the vapourware to avoid.
        return Programme(
            handle=handle,
            name=attrs.get("name", handle),
            url=f"https://hackerone.com/{handle}",
            bounty_table={},
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            offers_bounties=bool(attrs.get("offers_bounties", True)),
            accepts_new_reports=submission_state == "open",
            triage_active=attrs.get("triage_active"),
            state=attrs.get("state"),
            policy_text=attrs.get("policy", "") or "",
        )

    # Report submission

    def submit_report(self, report: DisclosureReport) -> SubmissionResult:
        """
        Submit a disclosure report to HackerOne.
        Returns a SubmissionResult with the new report ID on success.
        """
        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": report.title,
                    "vulnerability_information": report.body_markdown,
                    "impact": report.impact_statement,
                    "severity_rating": report.vulnerability.severity.value,
                    "weakness_id": report.weakness_id,
                },
                "relationships": {
                    "program": {
                        "data": {
                            "type": "program",
                            # FIX: was {"attributes": {"handle": ...}} -> 422 on every submit
                            "id": report.programme_handle,
                        }
                    }
                },
            }
        }

        try:
            response = self._post("/reports", payload)
            report_id = response["data"]["id"]
            logger.info("Submitted report %s to %s", report_id, report.programme_handle)
            return SubmissionResult(
                report_id=report_id,
                status=SubmissionStatus.SUBMITTED,
                h1_url=f"https://hackerone.com/reports/{report_id}",
                # FIX: submitted_at was not set, leaving it always None
                submitted_at=datetime.now(UTC),
            )
        except requests.HTTPError as exc:
            logger.error("Submission failed: %s", exc.response.text)
            return SubmissionResult(
                status=SubmissionStatus.PENDING,
                error=str(exc),
            )

    def list_reports(self, programme_handle: str, page_size: int = 25) -> list[dict]:
        """List recent reports for a programme - used for duplicate detection."""
        data = self._get(
            "/hackers/me/reports",
            params={"filter[program][]": programme_handle, "page[size]": page_size},
        )
        return list(data.get("data", []))

    def get_report_status(self, report_id: str) -> SubmissionStatus:
        """Poll the status of a previously submitted report."""
        data = self._get(f"/reports/{report_id}")
        state = data.get("data", {}).get("attributes", {}).get("state", "new")
        status_map = {
            "new": SubmissionStatus.SUBMITTED,
            "triaged": SubmissionStatus.TRIAGED,
            "resolved": SubmissionStatus.RESOLVED,
            "duplicate": SubmissionStatus.DUPLICATE,
            "not-applicable": SubmissionStatus.NOT_APPLICABLE,
            "informative": SubmissionStatus.INFORMATIVE,
        }
        return status_map.get(state, SubmissionStatus.PENDING)


# Module-level singleton - import this rather than H1Client directly
h1 = H1Client()
