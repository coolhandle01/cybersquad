"""
squad/programme_manager/tools/selection.py - the programme-selection surface.

Tools the Programme Manager uses to pick the highest-value H1 programme:
``Browse HackerOne Programmes`` surveys the catalog with cheap previews,
``Hydrate HackerOne Programme`` pulls full detail for a shortlisted
handle, and ``Save Selected Programme`` binds the choice for every
downstream agent.
"""

import shutil

from pydantic import BaseModel, Field

import runtime
from models.h1 import Programme, ProgrammePreview, ScopeType, SubmissionState
from squad import cyber_tool
from tools.h1_api import h1


class _BrowseProgrammesArgs(BaseModel):
    """Explicit args_schema for the Browse HackerOne Programmes tool."""

    asset_type: ScopeType | None = Field(
        default=None,
        description=(
            "H1 ``filter[asset_type]`` value, typed as the codebase's"
            " ``ScopeType`` StrEnum (lowercase Python-side: ``ScopeType."
            " WILDCARD`` has value ``'wildcard'``). The wrapper uppercases"
            " on the wire to match H1's filter format. Common picks:"
            " ``WILDCARD`` for broad surface coverage, ``URL`` for a"
            " single application target, ``IP_ADDRESS`` / ``CIDR`` for"
            " network-tier targets. Omit (None) to accept any asset type"
            " - the H1 default. A wrong value here pulls the wrong"
            " shortlist."
        ),
    )
    bookmarked: bool | None = Field(
        default=None,
        description=(
            "Restrict to programmes the authenticated user has bookmarked."
            " Useful when the operator has curated a shortlist server-side."
            " Omit (None) for the H1 default, which does not filter on"
            " bookmarks."
        ),
    )
    offers_bounties: bool | None = Field(
        default=None,
        description=(
            "Pass True to exclude VDPs (vulnerability disclosure programmes"
            " that pay no bounty). Omit (None) to accept both bounty and"
            " VDP programmes - the H1 default."
        ),
    )
    submission_state: SubmissionState | None = Field(
        default=None,
        description=(
            "H1 ``filter[submission_state]`` value, typed as the"
            " ``SubmissionState`` StrEnum. ``OPEN`` excludes paused and"
            " disabled programmes; almost always pass ``OPEN`` -"
            " submitting against a paused or disabled programme wastes"
            " the submission. Omit (None) to accept any state."
        ),
    )
    sort: str | None = Field(
        default=None,
        description=(
            "H1 JSON:API sort key. Prefix with '-' for descending."
            " Common values: '-launched_at' (newest first),"
            " 'launched_at' (oldest first), '-resolved_report_count' (most"
            " active triage)."
        ),
    )
    limit: int | None = Field(
        default=None,
        description=(
            "Cap on total previews returned across pages. Omit (None) to use"
            " the configured default (``config.h1.max_programmes``)."
            " This is a server-side pagination ceiling, not a per-request"
            " page size."
        ),
    )


@cyber_tool("Browse HackerOne Programmes", args_schema=_BrowseProgrammesArgs)
# CrewAI builds the tool's JSON schema from this signature; each filter has
# to be a named parameter so the LLM can discover and pass it. Collapsing
# into a single dict argument would force the agent to guess valid filter
# keys.
# pylint: disable=R0913,R0917
def browse_programmes_tool(
    asset_type: ScopeType | None = None,
    bookmarked: bool | None = None,
    offers_bounties: bool | None = None,
    submission_state: SubmissionState | None = None,
    sort: str | None = None,
    limit: int | None = None,
) -> list[ProgrammePreview]:
    """
    Survey the accessible H1 catalog with lightweight previews - one HTTP
    call per page, no per-programme detail fetch. Cheap, so use this first
    to see what is out there before deciding which programmes are worth
    paying to hydrate.

    Each preview carries handle, name, offers_bounties, submission_state,
    state, and bookmarked - enough to narrow on access mode and bounty
    posture before pulling policy_text and scope.

    Filter kwargs map to H1 filter[*] query params on /hackers/programs and
    are sent to the server; the H1 default applies when a kwarg is omitted.
      - asset_type: a ScopeType (e.g. ScopeType.WILDCARD)
      - bookmarked: True for programmes you have bookmarked
      - offers_bounties: True to exclude VDPs
      - submission_state: SubmissionState.OPEN to exclude paused/disabled
      - sort: e.g. "-launched_at" for newest first
      - limit: cap on total previews (default config.h1.max_programmes)

    Returns a list of ProgrammePreview. Hydrate shortlisted handles with
    hydrate_programme_tool.
    """
    # H1's filter API expects uppercase asset_type values (URL, WILDCARD,
    # ...); ScopeType is the parsed Python-side shape with lowercase
    # values. Normalise here so the agent passes the same enum it sees on
    # parsed Programme objects, and the wire form stays H1's expected
    # uppercase.
    asset_type_wire = asset_type.value.upper() if asset_type is not None else None
    return list(
        h1.browse_programmes(
            asset_type=asset_type_wire,
            bookmarked=bookmarked,
            offers_bounties=offers_bounties,
            submission_state=submission_state.value if submission_state is not None else None,
            sort=sort,
            limit=limit,
        )
    )


class _HydrateProgrammeArgs(BaseModel):
    """Explicit args_schema for the Hydrate HackerOne Programme tool."""

    handle: str = Field(
        description=(
            "Exact HackerOne programme handle as it appears in the URL"
            " (lowercase, no slashes, no spaces, no protocol or host). For"
            " ``https://hackerone.com/security`` the handle is ``security``."
            " The H1 API treats the handle as the authoritative key for the"
            " programme detail endpoint; an unknown or mis-cased handle"
            " returns 404 and the PM walks past the programme it should have"
            " hydrated."
        ),
    )


@cyber_tool("Hydrate HackerOne Programme", args_schema=_HydrateProgrammeArgs)
def hydrate_programme_tool(handle: str) -> Programme:
    """
    Fetch full programme detail for one handle - bounty_table, structured
    scope, policy text, response/payout stats. One HTTP call.

    Expensive relative to browse_programmes_tool, so reserve for candidates
    the browse step has already shortlisted. The hydrated programme is
    cached so save_programme_tool can copy it into the run directory.
    """
    prog = h1.hydrate_programme(handle)
    cache_path = runtime.programme_cache_path(prog.handle)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(prog.model_dump_json(), encoding="utf-8")
    return prog


class _SaveProgrammeArgs(BaseModel):
    """Explicit args_schema for the Save Selected Programme tool."""

    handle: str = Field(
        description=(
            "Exact HackerOne programme handle as it appears in the URL"
            " (lowercase, no slashes, no spaces). Must match a handle that"
            " was already hydrated this run - the cached ``programme.json``"
            " is keyed by handle and a mismatch means downstream agents see"
            " an empty run directory and reason against a programme that"
            " was never selected."
        ),
    )


@cyber_tool("Save Selected Programme", args_schema=_SaveProgrammeArgs)
def save_programme_tool(handle: str) -> str:
    """
    Record the selected programme for downstream agents. Binds
    runtime.programme_handle, creates the run directory, and copies the
    cached programme.json into it. Returns the absolute path to the run
    directory.
    """
    runtime.bind_programme(handle)
    run_dir = runtime.run_dir()
    run_dir.mkdir(parents=True, exist_ok=True)
    cache = runtime.programme_cache_path(handle)
    if cache.exists():
        shutil.copy(cache, run_dir / "programme.json")
    return str(run_dir)
