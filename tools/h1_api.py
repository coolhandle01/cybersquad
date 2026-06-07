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
        self._session = requests.Session()
        self._session.auth = self._auth
        self._session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": http.user_agent(),
            }
        )

    # Internal helpers

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
        path = "/hackers/programs"

        while path and len(results) < config.h1.max_programmes:
            data = self._get(path, params)
            results.extend(data.get("data", []))
            path = self._next_path(data)
            params = {}

        return results[: config.h1.max_programmes]

    def get_programme_policy(self, handle: str) -> dict:
        """Fetch full policy detail for a given programme handle."""
        return self._get(f"/hackers/programs/{handle}")

    def get_structured_scope(self, handle: str) -> dict:
        """Fetch the structured scope (in/out) for a programme."""
        return self._get(f"/hackers/programs/{handle}/structured_scopes")

    def get_programme_detail(self, handle: str) -> dict:
        """Fetch programme detail with bounty_table and structured_scopes inline.

        Halves the round-trips per programme compared to calling
        get_programme_policy + get_structured_scope separately.
        """
        return self._get(
            f"/hackers/programs/{handle}",
            params={"include": "bounty_table,structured_scopes"},
        )

    def browse_programmes(
        self,
        *,
        asset_type: str | None = None,
        bookmarked: bool | None = None,
        offers_bounties: bool | None = None,
        submission_state: str | None = None,
        sort: str | None = None,
        limit: int | None = None,
        page_size: int = 25,
    ) -> list[ProgrammePreview]:
        """Paginate through accessible programmes returning lightweight previews.

        Cheap by design - one HTTP call per page, no per-programme detail fetch.
        The caller surveys the catalog, shortlists handles, then pays for
        hydration on just those candidates via hydrate_programme.

        Filter kwargs map to H1's JSON:API filter[*] query params on
        /hackers/programs. Each kwarg is omitted from the request entirely
        when None, so the H1 default applies. Booleans are sent as lowercase
        "true"/"false" - the wire form filter[*] params expect.

        limit caps the total returned previews across pages; defaults to
        config.h1.max_programmes. page_size is the per-request page size,
        not the cap.
        """
        cap = limit if limit is not None else config.h1.max_programmes

        params: dict[str, object] = {"page[size]": page_size}
        # FIXME: the exact H1 filter[*] keys for /hackers/programs are not
        # exhaustively confirmed against a captured request - tracked in #43.
        # The four below match attributes the list endpoint is known to
        # expose; passing an unknown filter key would be silently ignored by
        # H1, so the worst case is "filter did nothing".
        _filter_kwargs = {
            "asset_type": asset_type,
            "bookmarked": bookmarked,
            "offers_bounties": offers_bounties,
            "submission_state": submission_state,
        }
        for key, value in _filter_kwargs.items():
            if value is None:
                continue
            params[f"filter[{key}]"] = str(value).lower() if isinstance(value, bool) else str(value)
        if sort is not None:
            params["sort"] = sort

        previews: list[ProgrammePreview] = []
        path: str | None = "/hackers/programs"
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
            # Pagination links from H1 already encode page params; subsequent
            # calls should not redundantly carry the initial filter dict.
            params = {}

        return previews

    def hydrate_programme(self, handle: str) -> Programme:
        """Fetch full detail for one programme and return a typed Programme.

        Pulls bounty_table + structured_scopes inline via the detail endpoint's
        include parameter. One HTTP call. Use after browse_programmes to drill
        into a specific candidate the PM wants to score.
        """
        detail = self.get_programme_detail(handle)
        detail_data = detail.get("data", {})
        included = detail.get("included", [])
        scope_data = {"data": [i for i in included if i.get("type") == "structured-scope"]}
        return self.parse_programme(detail_data, scope_data)

    # Data parsers

    def parse_programme(self, raw: dict, scope_data: dict) -> Programme:
        """Convert raw H1 API dicts into a typed Programme model."""
        attrs = raw.get("attributes", {})
        handle = attrs.get("handle", raw.get("id", "unknown"))

        bounty_table: dict[Severity, int] = {}
        for offer in attrs.get("bounty_table", {}).get("data", []):
            o_attrs = offer.get("attributes", {})
            sev_str = o_attrs.get("label", "medium").lower()
            amount = int(o_attrs.get("maximum_amount", 0) or 0)
            sev = _H1_SEVERITY_MAP.get(sev_str, Severity.MEDIUM)
            bounty_table[sev] = amount

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

        policy_text: str = attrs.get("policy", "") or ""

        offers_bounties: bool = bool(attrs.get("offers_bounties", True))
        submission_state: str = attrs.get("submission_state", "open") or "open"
        accepts_new_reports: bool = submission_state == "open"

        response_efficiency_pct: float | None = attrs.get("response_efficiency_percentage")
        avg_bounty_minutes: float | None = attrs.get("average_time_to_bounty_in_minutes")
        avg_time_to_bounty_days: float | None = (
            round(avg_bounty_minutes / (60 * 24), 1) if avg_bounty_minutes else None
        )
        avg_first_resp_minutes: float | None = attrs.get(
            "average_time_to_first_programme_response_in_minutes"
        )
        avg_time_to_first_response_days: float | None = (
            round(avg_first_resp_minutes / (60 * 24), 1) if avg_first_resp_minutes else None
        )
        total_cents: int | None = attrs.get("total_bounties_paid_in_cents")
        total_bounties_paid_usd: int | None = total_cents // 100 if total_cents else None
        triage_active: bool | None = attrs.get("triage_active")
        state: str | None = attrs.get("state")
        last_updated_str: str | None = attrs.get("updated_at")
        last_updated_at: datetime | None = (
            datetime.fromisoformat(last_updated_str.replace("Z", "+00:00"))
            if last_updated_str
            else None
        )

        return Programme(
            handle=handle,
            name=attrs.get("name", handle),
            url=f"https://hackerone.com/{handle}",
            bounty_table=bounty_table,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            offers_bounties=offers_bounties,
            accepts_new_reports=accepts_new_reports,
            response_efficiency_pct=response_efficiency_pct,
            avg_time_to_bounty_days=avg_time_to_bounty_days,
            avg_time_to_first_response_days=avg_time_to_first_response_days,
            total_bounties_paid_usd=total_bounties_paid_usd,
            triage_active=triage_active,
            last_updated_at=last_updated_at,
            state=state,
            policy_text=policy_text,
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

    def get_programme_stats(self, handle: str) -> dict:
        """Return response efficiency and payout stats for a programme."""
        data = self._get(f"/hackers/programs/{handle}")
        attrs = data.get("data", {}).get("attributes", {})
        return {
            "handle": handle,
            "response_efficiency_pct": attrs.get("response_efficiency_percentage"),
            "avg_time_to_first_response_minutes": attrs.get(
                "average_time_to_first_programme_response_in_minutes"
            ),
            "avg_time_to_bounty_minutes": attrs.get("average_time_to_bounty_in_minutes"),
            "avg_time_to_resolution_minutes": attrs.get("average_time_to_resolution_in_minutes"),
            "total_bounties_paid_cents": attrs.get("total_bounties_paid_in_cents"),
            "accepting_reports": attrs.get("state") == "public_mode",
        }

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
