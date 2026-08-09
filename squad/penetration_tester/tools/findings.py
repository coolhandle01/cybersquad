"""
squad/penetration_tester/tools/findings.py - the PT's Save Findings @cyber_tool
wrapper.

One tool, one responsibility: roll the accumulated ``RawFinding``
list from this session's probe runs into ``findings.json`` so the
Vulnerability Researcher's triage can consume it via ``List Raw
Findings`` / ``Read Raw Finding``. The writer-reader pair is the
contract the cybersquad-tool skill calls out.
"""

import json

from pydantic import BaseModel, Field

import runtime
from models import RawFinding
from squad import cyber_tool


class _SaveFindingsArgs(BaseModel):
    """Explicit args_schema for the PT's Save Findings tool.

    ``findings.json`` is the contract the VR's triage reads against;
    a mis-shaped findings list either refuses validation upstream
    (the wrapper re-validates every entry as ``RawFinding``) or
    persists an artefact the VR cannot load. The per-field
    description names that hand-off explicitly.
    """

    findings: list[RawFinding] = Field(
        description=(
            "Typed list of every raw finding the PT collected this"
            " run. Pass the accumulated list once after all probe"
            " tools have run - one call per session, not one call"
            " per probe. CrewAI hands the wrapper ``list[dict]`` from"
            " the LLM JSON; the body re-validates each entry as"
            " ``RawFinding`` so the persisted artefact is the canonical"
            " typed shape the VR's ``List Raw Findings`` / ``Read Raw"
            " Finding`` slicers depend on. A wrong-shape entry rejects"
            " at validation time, before the artefact is written."
        ),
    )


@cyber_tool("Save Findings", args_schema=_SaveFindingsArgs)
def save_findings_tool(findings: list[RawFinding]) -> str:
    """
    Write the collected raw findings to findings.json in the run directory.
    Call this once after all probe tools have run, passing the typed list
    of findings collected from the probe tools. Returns the relative
    filename for downstream agents.
    """
    out_path = runtime.run_dir() / "findings.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # CrewAI args-schema validation produces list[dict] from the LLM JSON
    # before invoking us; re-validate so the persisted artefact is the
    # canonical typed shape findings.json consumers depend on.
    validated = [RawFinding.model_validate(f) for f in findings]
    out_path.write_text(
        json.dumps([f.model_dump(mode="json") for f in validated]),
        encoding="utf-8",
    )
    return "findings.json"
