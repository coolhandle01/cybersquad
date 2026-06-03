"""
models.attack.forest - the VR's attack plan and its validation surface.

The forest of ``AttackTree`` goals the Penetration Tester *searches* (Sheyner
2002 MDP framing), plus the validation issue / report shapes and the
finalisation error raised when the plan cannot be persisted.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from models.attack.tree import AttackTree


class AttackForest(BaseModel):
    """The VR's attack plan - a forest of AttackTrees, one per goal.

    The OA describes the asset graph (``AttackGraph``); the VR finds
    the trees rooted at goals worth pursuing on that graph; the PT
    searches the forest for the shortest viable path to each goal
    (the kill chain - a derived projection, not a stored type).

    The PT's reasoning is closer to A* with a domain heuristic plus
    MDPs over attack graphs (Sheyner et al. 2002, *Automated Generation
    and Analysis of Attack Graphs*) than literal travelling-salesman,
    but the salesman intuition holds: optimise a route through a
    discovered topology, working backwards from the goal, with online
    re-planning as probes succeed or fail.

    Today a flat ``trees`` list with no inter-tree relations. Two
    forward-looking expansions land here when the VR matures:

    * Per-tree AND/OR subgoal decomposition (see ``AttackTree``).
    * Tree overlap sorting - trees sharing nodes on the underlying
      ``AttackGraph`` get ranked together so the PT's search amortises
      shared subgoals across goals (probe once, satisfy multiple
      kill-chain prerequisites).
    """

    programme_handle: str
    drafted_at: datetime
    trees: list[AttackTree]


class AttackForestValidationIssue(BaseModel):
    """One issue produced by attack-plan validation."""

    section: str
    severity: str  # "error" (blocks finalise) or "warning" (advisory)
    message: str


class AttackForestValidationReport(BaseModel):
    """Result of validating an AttackForest."""

    ok: bool
    issues: list[AttackForestValidationIssue] = Field(default_factory=list)


class AttackForestFinalisationError(RuntimeError):
    """Raised when an AttackForest cannot be persisted to attack_forest.json."""
