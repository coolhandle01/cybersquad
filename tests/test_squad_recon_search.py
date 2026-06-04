"""
tests/test_squad_recon_search.py - the #169 spike tool: vector search over
``recon.json`` (``recon_semantic_search_tool``).

The wrapper is thin: resolve the relative recon path under the run dir, hand the
file to a cached ``JSONSearchTool``, and wrap the retrieved text in the typed
``ReconSearchResult``. The actual embedding / vector index is third-party
(``crewai_tools``) and pulls a ~79MB ONNX model on first real use, so it is
mocked here - coverage is of the wrapping (path resolution, refusal conditions,
return shape, the per-file index cache), not of chromadb.

The ``args_schema`` contract is co-located in ``TestReconSearchArgsSchema``,
mirroring ``tests/test_squad_workspace_tools.py`` (the recon-search tool is
shared between the VR and PT rather than agent-scoped).
"""

from typing import ClassVar

import pytest
from pydantic import BaseModel, ValidationError

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clear_index_cache():
    """Drop the per-path JSONSearchTool cache around each test.

    The cache is module-level and keyed by resolved path; ``run_dir`` is a fresh
    ``tmp_path`` per test, so stale entries would not collide, but clearing keeps
    the mocked-tool identity assertions honest.
    """
    from squad.tools import recon_search

    recon_search._INDEX_CACHE.clear()
    yield
    recon_search._INDEX_CACHE.clear()


class _FakeJSONSearchTool:
    """Stand-in for ``crewai_tools.JSONSearchTool``.

    Records the ``json_path`` it indexed and the queries it ran, and returns a
    canned relevant-chunk string - enough to exercise the wrapper without the
    embedding backend.
    """

    instances: ClassVar[list["_FakeJSONSearchTool"]] = []

    def __init__(self, json_path=None, config=None, collection_name=None, **kwargs):
        self.json_path = json_path
        self.config = config
        self.collection_name = collection_name
        self.queries: list[str] = []
        _FakeJSONSearchTool.instances.append(self)

    def run(self, search_query: str) -> str:
        self.queries.append(search_query)
        return f"Relevant Content:\nchunk-for::{search_query}"


@pytest.fixture()
def fake_json_search(monkeypatch):
    """Patch ``crewai_tools.JSONSearchTool`` with the recording fake."""
    import crewai_tools

    _FakeJSONSearchTool.instances = []
    monkeypatch.setattr(crewai_tools, "JSONSearchTool", _FakeJSONSearchTool)
    return _FakeJSONSearchTool


class TestReconSemanticSearchTool:
    def test_returns_typed_result_with_retrieved_matches(self, run_dir, fake_json_search) -> None:
        from models import ReconSearchResult
        from squad import recon_semantic_search_tool

        (run_dir / "recon.json").write_text('{"subdomains": []}', encoding="utf-8")
        result = recon_semantic_search_tool.func("which hosts serve WordPress?")

        assert isinstance(result, ReconSearchResult)
        assert result.query == "which hosts serve WordPress?"
        assert result.recon_path == "recon.json"
        assert "chunk-for::which hosts serve WordPress?" in result.matches

    def test_indexes_the_resolved_recon_file(self, run_dir, fake_json_search) -> None:
        from squad import recon_semantic_search_tool

        (run_dir / "recon.json").write_text("{}", encoding="utf-8")
        recon_semantic_search_tool.func("anything")

        assert len(fake_json_search.instances) == 1
        assert fake_json_search.instances[0].json_path == str(run_dir / "recon.json")

    def test_caches_index_across_queries_on_same_file(self, run_dir, fake_json_search) -> None:
        """A second query against the same recon file reuses the built index."""
        from squad import recon_semantic_search_tool

        (run_dir / "recon.json").write_text("{}", encoding="utf-8")
        recon_semantic_search_tool.func("first")
        recon_semantic_search_tool.func("second")

        # One construction (indexing happens once), two queries on that instance.
        assert len(fake_json_search.instances) == 1
        assert fake_json_search.instances[0].queries == ["first", "second"]

    def test_raises_when_recon_missing(self, run_dir, fake_json_search) -> None:
        from squad import recon_semantic_search_tool

        with pytest.raises(FileNotFoundError, match="Finalise Recon"):
            recon_semantic_search_tool.func("anything")
        # No index built when the file does not exist.
        assert fake_json_search.instances == []

    def test_refuses_path_escape(self, run_dir, fake_json_search) -> None:
        from squad import recon_semantic_search_tool

        with pytest.raises(ValueError, match=r"must not contain '\.\.'"):
            recon_semantic_search_tool.func("anything", "../etc/passwd")


class TestReconSearchArgsSchema:
    """Contract tests for the shared tool's explicit ``args_schema``."""

    def test_every_field_has_description(self) -> None:
        from squad.tools.recon_search import _ReconSemanticSearchArgs

        for field_name, field_info in _ReconSemanticSearchArgs.model_fields.items():
            desc = field_info.description
            assert desc, f"{field_name} missing Field(description=...)"
            assert isinstance(desc, str) and desc.strip(), f"{field_name} description is blank"

    def test_recon_path_defaults_to_recon_json(self) -> None:
        from squad.tools.recon_search import _ReconSemanticSearchArgs

        instance = _ReconSemanticSearchArgs.model_validate({"query": "anything"})
        assert instance.recon_path == "recon.json"

    def test_query_is_required(self) -> None:
        from squad.tools.recon_search import _ReconSemanticSearchArgs

        with pytest.raises(ValidationError):
            _ReconSemanticSearchArgs.model_validate({})

    def test_schema_is_a_basemodel(self) -> None:
        from squad.tools.recon_search import _ReconSemanticSearchArgs

        assert issubclass(_ReconSemanticSearchArgs, BaseModel)
