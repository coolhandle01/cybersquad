"""
tools/h1_api.py — HackerOne API wrapper.

Covers everything the pipeline needs:
  - Listing & ranking programmes
  - Fetching programme policy / scope
  - Submitting reports
  - Polling submission status

H1 API docs: https://api.hackerone.com/docs/v1
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import cast

import requests
from requests.auth import HTTPBasicAuth

from config import config
from models import (
    DisclosureReport,
    Programme,
    ScopeItem,
    ScopeType,
    Severity,
    SubmissionResult,
    SubmissionStatus,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity mapping — H1 uses strings, we use our enum
# ---------------------------------------------------------------------------
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
    "ANDROID": ScopeType.ANDROID,
    "IOS": ScopeType.IOS,
    "OTHER": ScopeType.OTHER,
}


class H1Client:
    """
    Thin, authenticated wrapper around the HackerOne v1 REST API.
    All methods raise on non-2xx responses after logging the error.
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
            }
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self._base}{path}"
        resp = self._session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        return cast(dict, resp.json())

    def _post(self, path: str, payload: dict) -> dict:
        url = f"{self._base}{path}"
        resp = self._session.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        return cast(dict, resp.json())

    # ------------------------------------------------------------------
    # Programme discovery
    # ------------------------------------------------------------------

    def list_programmes(self, page_size: int = 25) -> list[dict]:
        """
        Return raw programme data from /programs.
        Paginates until we have at least config.h1.max_programmes results.
        """
        results: list[dict] = []
        params = {"page[size]": page_size}
        path = "/programs"

        while path and len(results) < config.h1.max_programmes:
            data = self._get(path, params)
            results.extend(data.get("data", []))
            path = data.get("links", {}).get("next", None)
            params = {}

        return results[: config.h1.max_programmes]

    def get_programme_policy(self, handle: str) -> dict:
        """Fetch full policy detail for a given programme handle."""
        return self._get(f"/programs/{handle}")

    def get_structured_scope(self, handle: str) -> dict:
        """Fetch the structured scope (in/out) for a programme."""
        return self._get(f"/programs/{handle}/structured_scopes")

    # ------------------------------------------------------------------
    # Data parsers
    # ------------------------------------------------------------------

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
            scope_item = ScopeItem(
                asset_identifier=i_attrs.get("asset_identifier", ""),
                asset_type=_H1_SCOPE_TYPE_MAP.get(
                    i_attrs.get("asset_type", "OTHER"), ScopeType.OTHER
                ),
                eligible_for_bounty=i_attrs.get("eligible_for_bounty", False),
                instruction=i_attrs.get("instruction"),
            )
            if i_attrs.get("eligible_for_submission", True):
                in_scope.append(scope_item)
            else:
                out_of_scope.append(scope_item)

        policy_text: str = attrs.get("policy", "") or ""
        allows_auto = not any(
            kw in policy_text.lower()
            for kw in ["no automated", "automated scanning prohibited", "no scanners"]
        )

        return Programme(
            handle=handle,
            name=attrs.get("name", handle),
            url=f"https://hackerone.com/{handle}",
            bounty_table=bounty_table,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            allows_automated_scanning=allows_auto,
        )

    # ------------------------------------------------------------------
    # Report submission
    # ------------------------------------------------------------------

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
                            # FIX: was {"attributes": {"handle": ...}} → 422 on every submit
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
                submitted_at=datetime.utcnow(),
            )
        except requests.HTTPError as exc:
            logger.error("Submission failed: %s", exc.response.text)
            return SubmissionResult(
                status=SubmissionStatus.PENDING,
                error=str(exc),
            )

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


# ---------------------------------------------------------------------------
# Module-level singleton — import this rather than H1Client directly
# ---------------------------------------------------------------------------
h1 = H1Client()
