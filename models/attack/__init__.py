"""
models.attack - the three attack-surface formalisms (OA -> VR -> PT).

The naming trio ``academic-grounding.md`` ties together, one module per
formalism so the agent boundary the data crosses is legible from the import
line:

| Module | Formalism | Author -> consumer |
|---|---|---|
| ``models.attack.graph`` | ``AttackGraph`` - the asset graph *described* | OA -> VR |
| ``models.attack.tree`` | ``AttackTree`` - the per-goal hypothesis *found* | VR -> PT |
| ``models.attack.forest`` | ``AttackForest`` (+ validation) *searched* | VR -> PT, triage |

``AttackGraph`` composes the OAM asset shapes from ``models.asset`` but is not
itself an OAM asset - it is the Sheyner-style bundle that wraps them. This
``__init__`` is the public re-export surface, so ``from models.attack import
X`` (and the ``from models import X`` re-export in ``models/__init__``) keep
working across every consumer unchanged.

The intra-package import order is a DAG: ``tree`` / ``graph`` are leaves;
``forest`` builds on ``tree``. No cycles, so no ``model_rebuild`` is needed.
"""

from __future__ import annotations

from models.attack.forest import (
    AttackForest,
    AttackForestFinalisationError,
    AttackForestValidationIssue,
    AttackForestValidationReport,
)
from models.attack.graph import AttackGraph
from models.attack.tree import AttackTree

__all__ = [
    "AttackForest",
    "AttackForestFinalisationError",
    "AttackForestValidationIssue",
    "AttackForestValidationReport",
    "AttackGraph",
    "AttackTree",
]
