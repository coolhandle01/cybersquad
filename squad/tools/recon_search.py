"""squad/tools/recon_search.py - the #169 spike: vector search over ``recon.json``.

A *complement to* the typed slicers (``Recon Endpoints`` / ``Recon Open Ports`` /
``Recon Subdomains``), not a replacement. Those let the agent pick a known filter
axis (``status=200``, ``tech="wordpress"``); this lets it ask in prose ("which
login pages serve WordPress?", "endpoints serving JSON over plain HTTP?") and get
the semantically nearest chunks of the same ``recon.json`` back. The spike
question (#169): does the vector path unlock cross-cutting queries the typed path
cannot express as a filter, or just give the agent another way to ask the same
things?

Shape decisions, all driven by the spike framing:

* **Single document, not the per-host store.** ``JSONSearchTool`` (a
  ``crewai_tools`` ``RagTool``) indexes *one* JSON file. The consolidated
  ``recon.json`` bundle is self-contained - every record carries its host inline
  - so it embeds coherently. The atomic ``assets/<fqdn>/*.json`` facets are the
  wrong target: each is tiny and context-stripped (the host lives in the
  *directory name*, not the file body), so "ports on api.example.com" cannot
  retrieve the right file. The typed ``load_host_*`` readers own that store; this
  tool deliberately does not touch it.

* **Local embedder by default (no key, no spend).** ``JSONSearchTool``'s default
  embedder is OpenAI ``text-embedding-3-small`` (needs ``OPENAI_API_KEY``), which
  this Anthropic-only project does not carry. We default to chromadb's local
  ``onnx`` all-MiniLM embedder instead: no API key, no per-query embedding spend,
  runs offline (one ~79MB model download, cached). Override the provider via
  ``CYBERSQUAD_RECON_SEARCH_EMBEDDER`` if a hosted embedder is wanted for the A/B.

* **Size-dependent retrieval - read the A/B honestly.** Vector search only
  discriminates once the document spans many chunks. On a small ``recon.json``
  the whole file fits in one chunk and every query returns all of it - no better
  than ``Read Run File``. The payoff only appears on the large (~100KB+) real
  artefacts; judge the spike on those, not on a toy surface.

Wired through ``@cyber_tool`` (not registered as a bare ``JSONSearchTool``)
because it needs workspace-aware path resolution: ``run_dir()`` is bound mid-run,
so the path is resolved lazily at call time via ``resolve_run_path`` - the same
relative-path-only contract the typed slicers honour, so the agent never passes
an absolute path.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field

from models import ReconSearchResult
from squad import cyber_tool
from tools.workspace import resolve_run_path

# chromadb's local, no-API-key embedder (all-MiniLM-L6-v2 via ONNX). Overridable
# for the A/B - e.g. ``openai`` once a key is in the environment - via env so the
# default path stays free and offline without a config.py change for a spike.
_EMBEDDER_PROVIDER = os.getenv("CYBERSQUAD_RECON_SEARCH_EMBEDDER", "onnx")

# One indexed JSONSearchTool per resolved recon.json path. Indexing happens at
# construction (the ``add`` call), so caching keeps repeat queries in a run cheap;
# keyed by the resolved absolute path so two runs' recon.json never share an
# index. Populated lazily because the import-time cost (chromadb + the embedder
# model) should not land on every process that imports the squad surface.
_INDEX_CACHE: dict[str, object] = {}


def _search_tool(recon_file: Path) -> object:
    """Return the cached JSONSearchTool indexing ``recon_file`` (building once).

    Imported lazily: ``crewai_tools.JSONSearchTool`` pulls in chromadb and the
    embedder backend, a cost the squad's import graph should not pay just to
    register the tool.
    """
    key = str(recon_file)
    cached = _INDEX_CACHE.get(key)
    if cached is not None:
        return cached

    from crewai_tools import JSONSearchTool

    tool = JSONSearchTool(
        json_path=key,
        config={"embedding_model": {"provider": _EMBEDDER_PROVIDER, "config": {}}},
        # Unique collection per path so a process that searches two runs' recon
        # files does not blend their chunks into one default-named collection.
        collection_name=f"recon_search_{abs(hash(key))}",
    )
    _INDEX_CACHE[key] = tool
    return tool


class _ReconSemanticSearchArgs(BaseModel):
    """Explicit args_schema for the Recon Semantic Search tool."""

    query: str = Field(
        description=(
            "A natural-language question about the recon surface - the way you"
            " would ask a teammate, not a filter. Use this when the slice you"
            " want does not fit the typed slicers' axes (status / tech / host"
            " substring): cross-cutting questions like 'which endpoints serve"
            " JSON over plain HTTP?' or 'which hosts run an unusual tech"
            " combination?'. For a single known axis (all 200s, all WordPress)"
            " prefer ``Recon Endpoints`` - it is exact, free, and deterministic."
        ),
    )
    recon_path: str = Field(
        default="recon.json",
        description=(
            "Relative path to the OSINT Analyst's ``recon.json`` in the current"
            " run directory (the consolidated artefact ``Finalise Recon`` wrote)."
            " Pass ``recon.json`` unless a non-default writer produced it."
            " Absolute paths and any segment containing ``..`` are rejected by the"
            " workspace layer. The per-host ``assets/<fqdn>/`` facet files are not"
            " a valid target here - query those via the typed List Host * tools."
        ),
    )


@cyber_tool("Recon Semantic Search", args_schema=_ReconSemanticSearchArgs)
def recon_semantic_search_tool(query: str, recon_path: str = "recon.json") -> ReconSearchResult:
    """
    Vector-search the OSINT Analyst's ``recon.json`` in natural language and get
    the semantically nearest chunks back. A complement to the typed slicers
    (``Recon Endpoints`` / ``Recon Open Ports`` / ``Recon Subdomains``): reach
    for those when your question fits a known filter axis; reach for this for the
    cross-cutting questions a filter cannot phrase.

    Returns a ``ReconSearchResult`` carrying the query, the recon path, and the
    retrieved ``matches`` text. The matches are relevant *chunks*, not the parsed
    asset shapes - read them as evidence to orient the next probe, then confirm
    specifics with a typed slicer. On a small recon surface retrieval may return
    most of the file; its value grows with the size of the inventory.

    Refuses (raises) if ``recon_path`` is absolute, escapes the run directory, or
    does not exist - finalise recon first, and pass the bare ``recon.json``.
    """
    recon_file = resolve_run_path(recon_path)
    if not recon_file.is_file():
        raise FileNotFoundError(
            f"{recon_path!r} not found in the run directory; the OSINT Analyst must "
            "Finalise Recon before the recon surface can be searched"
        )
    tool = _search_tool(recon_file)
    matches = tool.run(search_query=query)  # type: ignore[attr-defined]
    return ReconSearchResult(query=query, recon_path=recon_path, matches=matches)
