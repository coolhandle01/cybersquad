"""
squad/programme_manager/tools/selection.py - the programme-selection surface.

Tools the Programme Manager uses to pick the highest-value H1 programme:
``Browse HackerOne Programmes`` surveys the catalog with cheap previews,
``Hydrate HackerOne Programme`` pulls full detail for a shortlisted
handle, and ``Save Selected Programme`` binds the choice for every
downstream agent.
"""

from pydantic import BaseModel, Field

import runtime
from models.h1 import Programme, ProgrammePreview, SubmissionState
from squad import cyber_tool
from tools.h1_api import h1

# Programmes hydrated during this run, keyed by handle. The PM hydrates several
# candidates to score them, then saves exactly one. Holding the hydrated objects
# in memory keeps that hydrate->save handoff inside the agent WITHOUT writing a
# programme.json per candidate: the single selection save_programme_tool writes
# to the run directory is then the only programme.json on disk - the
# one-typed-artefact-per-stage contract the README documents, and the pre-#115
# behaviour (one programme.json when the PM is done, not one per hydrated handle).
_hydrated_this_run: dict[str, Programme] = {}


class _BrowseProgrammesArgs(BaseModel):
    """Explicit args_schema for the Browse HackerOne Programmes tool."""

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
            "A ``SubmissionState`` StrEnum naming the report window:"
            " ``OPEN`` for programmes accepting reports, paused/disabled"
            " for those that are not. Omit (None) to leave it unset."
        ),
    )
    limit: int | None = Field(
        default=None,
        description=(
            "Cap on how many previews you get back across all pages. Omit"
            " (None) to use the configured default. This bounds the total"
            " returned to you; it is not a per-request page size."
        ),
    )


@cyber_tool("Browse HackerOne Programmes", args_schema=_BrowseProgrammesArgs)
# CrewAI builds the tool's JSON schema from this signature; each filter has
# to be a named parameter so the LLM can discover and pass it. Collapsing
# into a single dict argument would force the agent to guess valid filter
# keys.
def browse_programmes_tool(
    bookmarked: bool | None = None,
    offers_bounties: bool | None = None,
    submission_state: SubmissionState | None = None,
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

    The filters (bookmarked, offers_bounties, submission_state) narrow the
    catalog. H1 does not filter its list server-side, so they are applied here
    against each preview: a programme that does not match every filter you set
    is dropped before you see it. offers_bounties=True drops VDPs;
    submission_state=OPEN drops paused/disabled programmes. limit caps how many
    previews come back.

    Returns a list of ProgrammePreview. Hydrate only the strongest shortlisted
    handles with hydrate_programme_tool.
    """
    return list(
        h1.browse_programmes(
            bookmarked=bookmarked,
            offers_bounties=offers_bounties,
            submission_state=submission_state.value if submission_state is not None else None,
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
    Fetch full programme detail for one handle - access/policy attributes,
    structured scope (in and out), explicit scope exclusions, and policy text.
    Three HTTP calls (programme detail, structured scopes, scope exclusions).
    Judge a programme's value from its scope, policy, and access signals.

    Expensive relative to browse_programmes_tool, so reserve for candidates
    the browse step has already shortlisted. The hydrated programme is held in
    memory (not written to disk) so save_programme_tool can persist the one you
    finally select - hydrating ten candidates must not leave ten programme.json
    files behind; the run gets exactly one, written by save.
    """
    prog = h1.hydrate_programme(handle)
    _hydrated_this_run[prog.handle] = prog
    return prog


class _SaveProgrammeArgs(BaseModel):
    """Explicit args_schema for the Save Selected Programme tool."""

    handle: str = Field(
        description=(
            "Exact HackerOne programme handle as it appears in the URL"
            " (lowercase, no slashes, no spaces). Must match a handle you"
            " already hydrated this run - save persists the in-memory hydrated"
            " programme, so a handle that was never hydrated has nothing to"
            " write and is rejected."
        ),
    )


@cyber_tool("Save Selected Programme", args_schema=_SaveProgrammeArgs)
def save_programme_tool(handle: str) -> str:
    """
    Record the selected programme for downstream agents. Binds
    runtime.programme_handle, creates the run directory, and writes the single
    selected programme.json into it. Returns the absolute path to the run
    directory. This is the only programme.json that reaches disk - one per run,
    not one per hydrated candidate.
    """
    prog = _hydrated_this_run.get(handle)
    if prog is None:
        # Fail loud instead of silently creating an empty run directory. A
        # handle not in the hydrated set means hydrate_programme_tool was never
        # run (or failed) for it, so there is nothing to persist - and a save
        # that returns success while writing no programme.json is exactly what
        # lets the select task "finish" with no artefact, only to fail the
        # downstream guardrail. Surfacing it here lets the agent re-hydrate.
        raise ValueError(
            f"No hydrated programme for handle {handle!r}; run "
            f"'Hydrate HackerOne Programme' for this exact handle first. "
            f"Saving without a hydrated programme would write no programme.json."
        )
    runtime.bind_programme(handle)
    run_dir = runtime.run_dir()
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "programme.json").write_text(prog.model_dump_json(), encoding="utf-8")
    return str(run_dir)
