"""squad/osint_analyst/tools - the OSINT Analyst's CrewAI wrapper layer.

One module per cohesive responsibility (``discovery`` / ``curation`` /
``enrichment``); the agent ``__init__`` imports each wrapper and
assembles ``MEMBER.tools``. The kernels these wrap live in the top-level
``tools/`` package.
"""
