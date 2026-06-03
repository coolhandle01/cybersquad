"""squad/penetration_tester/tools - the Penetration Tester's CrewAI wrapper layer.

Holds the ``@pentest_tool`` probe wrappers (``probes``), the
``@cyber_tool`` cloud / infra wrappers (``cloud``), the recon slicers
(``recon``), the ``Save Findings`` writer (``findings``), and the
``pentest_tool`` decorator + both-shapes adapters (``_decorator``). The
agent ``__init__`` imports each wrapper and assembles ``MEMBER.tools``;
the kernels these wrap live in the top-level ``tools/`` package.
"""
