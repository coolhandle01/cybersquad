"""squad/tools - the shared CrewAI wrapper layer.

Holds the ``@cyber_tool`` wrappers every squad member can use, decoupled
from any single member's package. The kernels these wrap live in the
top-level ``tools/`` package; this layer is only the CrewAI-facing
adaptation (typed args_schema, workspace IO, scope guard).

Currently the run-workspace surface (``List Run Files`` / ``Read Run
File`` / ``Read Attack Plan``) and the shared ``current_programme()``
loader, in ``workspace_tools``.
"""
