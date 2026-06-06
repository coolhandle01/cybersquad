"""squad/technical_author/tools - the Technical Author's CrewAI wrapper layer.

The report-authoring surface (``authoring``): evidence sanitisation,
CWE / OWASP guidance lookups, CVSS scoring, prior-art listing, and the
``Draft Vulnerability Report`` / ``Finalise Reports`` writers. The agent
``__init__`` imports each wrapper and assembles ``MEMBER.tools``.
"""
