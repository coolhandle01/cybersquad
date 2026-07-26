"""
tests/test_squad_workspace_tools.py - exercise the shared workspace @tool
wrappers (``read_run_filelist_tool`` / ``read_run_file_tool`` /
``read_attack_forest_tool``) plus the ``current_programme()`` reader and the
``@cyber_tool`` auto-detected scope-filter mechanism that builds on it.

The wrappers are thin: unmarshal JSON, call into tools/workspace helpers,
serialise the result. Coverage here is regression coverage of the wrapping
itself; the underlying helpers are exercised in ``tests/test_workspace.py``.

The ``args_schema`` contract for the same three wrappers lives in
``TestWorkspaceArgsSchemas`` below - aligned with the per-agent
``test_args_schemas.py`` shape used elsewhere, but co-located with the
behavioural tests because the workspace tools are shared rather than
agent-scoped.
"""

import pytest
from pydantic import BaseModel, ValidationError

pytestmark = pytest.mark.unit


class TestSharedWorkspaceTools:
    def test_read_run_filelist_tool(self, run_dir) -> None:
        from models import RunFile
        from squad import read_run_filelist_tool

        (run_dir / "recon.json").write_text("{}", encoding="utf-8")
        result = read_run_filelist_tool.func()
        assert result == [RunFile(name="recon.json", size_bytes=2)]

    def test_read_run_file_tool(self, run_dir) -> None:
        from models import RunFileContent
        from squad import read_run_file_tool

        (run_dir / "recon.json").write_text("hello", encoding="utf-8")
        result = read_run_file_tool.func("recon.json")
        assert isinstance(result, RunFileContent)
        assert result.content == "hello"
        assert result.size_bytes == 5

    def test_read_run_file_tool_refuses_escape(self, run_dir) -> None:
        from squad import read_run_file_tool

        with pytest.raises(ValueError, match=r"must not contain '\.\.'"):
            read_run_file_tool.func("../etc/passwd")

    def test_read_attack_forest_tool_returns_typed_plan(self, attack_forest, run_dir) -> None:
        from models.attack import AttackForest
        from squad import read_attack_forest_tool

        (run_dir / "attack_forest.json").write_text(
            attack_forest.model_dump_json(), encoding="utf-8"
        )
        result = read_attack_forest_tool.func()
        assert isinstance(result, AttackForest)
        assert result.programme_handle == attack_forest.programme_handle
        assert len(result.trees) == len(attack_forest.trees)
        assert result.trees[0].probe == attack_forest.trees[0].probe
        assert result.trees[0].expected_ceiling == attack_forest.trees[0].expected_ceiling

    def test_read_attack_forest_tool_raises_when_missing(self, run_dir) -> None:
        from squad import read_attack_forest_tool

        with pytest.raises(FileNotFoundError, match="attack plan not found"):
            read_attack_forest_tool.func()


class TestCurrentProgramme:
    """``current_programme()`` reads the PM's run-dir snapshot.

    The PM's Save Selected Programme writes ``programme.json`` to the
    run directory at run start. Every downstream agent and every
    ``@cyber_tool(scope_filter=...)`` wrapper sources its Programme
    through ``current_programme()``; no second H1 API call.
    """

    def test_returns_programme_from_run_dir(self, programme, run_dir) -> None:
        from squad.tools.workspace_tools import current_programme

        (run_dir / "programme.json").write_text(programme.model_dump_json(), encoding="utf-8")
        result = current_programme()
        assert result.handle == programme.handle
        assert result.in_scope == programme.in_scope

    def test_raises_when_programme_json_missing(self, run_dir) -> None:
        from squad.tools.workspace_tools import current_programme

        with pytest.raises(FileNotFoundError):
            current_programme()


# Scope-guard behavioural coverage lives in ``tests/tools/recon/test_scope.py``
# ``TestInScopeTypedAliases`` - it exercises the ``TargetFQDNs`` /
# ``TargetEndpoints`` / ``TargetFQDN`` / ``TargetEndpoint`` typed
# aliases that are the scope guard. ``cyber_tool`` itself is a thin
# args_schema attacher now, exercised end-to-end via every
# wrapper test.


# Tool-name -> explicit schema class. The workspace wrappers are shared
# rather than agent-scoped, so the closed-world structural check in each
# consuming agent's ``test_args_schemas.py`` covers the registry side;
# this block holds the schema-side contract.
def _load_workspace_schemas() -> dict[str, type[BaseModel]]:
    """Resolve the schemas lazily so the module imports without the env vars."""
    from squad.tools.workspace_tools import (
        _ListRunFilesArgs,
        _ReadAttackForestArgs,
        _ReadRunFileArgs,
    )

    return {
        "List Run Files": _ListRunFilesArgs,
        "Read Run File": _ReadRunFileArgs,
        "Read Attack Plan": _ReadAttackForestArgs,
    }


class TestWorkspaceArgsSchemas:
    """Contract tests for the shared workspace tools' explicit
    ``args_schema`` classes.

    The workspace wrappers are reachable from every agent's ``MEMBER.tools``;
    a mis-call costs a wrong artefact loaded (or the wrong agent reasoning
    over the wrong inputs). The per-field description on ``Read Run File``'s
    ``relative_path`` is the load-bearing signal that says "prefer the typed
    slicer when one exists".
    """

    def test_every_field_has_description(self) -> None:
        """Every field on every workspace schema carries a description.

        ``List Run Files`` and ``Read Attack Plan`` have no fields (the
        run directory and attack plan path are resolved from runtime
        state), so the loop trivially passes for them.
        """
        for tool_name, schema_cls in _load_workspace_schemas().items():
            for field_name, field_info in schema_cls.model_fields.items():
                desc = field_info.description
                assert desc, f"{tool_name}::{field_name} missing Field(description=...)"
                assert isinstance(desc, str) and desc.strip(), (
                    f"{tool_name}::{field_name} description is blank"
                )

    def test_list_run_files_accepts_empty_payload(self) -> None:
        """``List Run Files`` takes no parameters; the empty payload is canonical."""
        from squad.tools.workspace_tools import _ListRunFilesArgs

        instance = _ListRunFilesArgs.model_validate({})
        assert isinstance(instance, _ListRunFilesArgs)

    def test_read_attack_forest_accepts_empty_payload(self) -> None:
        """``Read Attack Plan`` takes no parameters; the empty payload is canonical."""
        from squad.tools.workspace_tools import _ReadAttackForestArgs

        instance = _ReadAttackForestArgs.model_validate({})
        assert isinstance(instance, _ReadAttackForestArgs)

    def test_read_run_file_accepts_relative_path(self) -> None:
        """``Read Run File`` accepts a bare relative-path string."""
        from squad.tools.workspace_tools import _ReadRunFileArgs

        instance = _ReadRunFileArgs.model_validate({"relative_path": "recon.json"})
        assert instance.relative_path == "recon.json"

    def test_read_run_file_rejects_missing_relative_path(self) -> None:
        """``relative_path`` is required - the wrapper has no default."""
        from squad.tools.workspace_tools import _ReadRunFileArgs

        with pytest.raises(ValidationError):
            _ReadRunFileArgs.model_validate({})
