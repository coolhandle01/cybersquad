"""
models.attack.tree - the Vulnerability Researcher's per-goal hypothesis.

The Schneier-1999 attack tree: a goal (probe + target) the Penetration Tester
searches for. The trees the VR *finds* on the OA's ``AttackGraph``; collected
into an ``AttackForest`` (the sibling module) the PT then searches.
"""

from __future__ import annotations

from pydantic import BaseModel, field_validator

from models.nvd import Severity


class AttackTree(BaseModel):
    """One probe-target hypothesis from the VR's research pass.

    Rooted at a goal (probe + target) the PT searches for. Today a
    degenerate tree - the root IS the leaf, all fields describe both
    the goal and the only executable step. The ``Tree`` name is
    forward-looking: once the VR starts emitting AND/OR subgoal
    decomposition ("RCE on api.example.com" -OR-> "SSRF -> internal
    Redis" / "auth bypass -> admin panel" / ...), an explicit
    ``children: list[AttackTree]`` slot lands here with a
    ``decomposition: Literal["AND", "OR"]`` discriminator (Schneier
    1999 attack-tree shape). The PT's kill chain becomes a derived
    path search from the root down to a viable leaf (backwards
    shortest-path / A* on the AttackForest, online re-planned as
    probes succeed or fail).
    """

    probe: str  # CVE id or vulnerability-class name, e.g. "CVE-2022-22965" or "reflected XSS"
    target: str  # hostname or URL drawn from recon
    expected_ceiling: Severity  # CRITICAL / HIGH / MEDIUM / LOW the probe could reach
    rationale: str  # 1-2 sentence "why and what to look for"
    recon_evidence: list[str]  # references to recon signals that justified this hypothesis

    @field_validator("recon_evidence")
    @classmethod
    def _strip_and_filter_evidence(cls, value: list[str]) -> list[str]:
        """Strip whitespace from every entry and drop empties.

        Lives on the model so every constructor (CrewAI args_schema
        validation, ``model_validate_json`` on a re-loaded attack plan,
        a direct ``AttackTree(...)`` call) sees the same cleaned
        list. Pairs with ``validate_attack_forest``'s
        ``if not tree.recon_evidence:`` hard error - a tree that was
        passed whitespace-only entries ends up with an empty list and
        the validator catches it, instead of the persisted artefact
        carrying junk the PT then has to reason around.
        """
        return [entry.strip() for entry in value if entry.strip()]
