# Architecture

## What this project does

cybersquad is a six-agent CrewAI pipeline that autonomously selects HackerOne bug bounty programmes, maps their attack surface, runs vulnerability scans, triages findings, writes professional disclosure reports, and submits them via the H1 API. Agents run sequentially; each passes structured output to the next via CrewAI's `context` chaining.

## Key files

| File | Purpose |
|---|---|
| `main.py` | CLI entrypoint. Calls `check_env()` before importing crew - keep it that way. |
| `config.py` | All env-var reading lives here. Singleton: `from config import config`. |
| `models.py` | Pydantic contracts between agents. Change these carefully - they cross agent boundaries. |
| `crew.py` | Assembles the `Crew`: builds LLM, agents, tasks. No module-level side effects. |
| `tasks.py` | Pipeline wiring - context dependencies and `human_input` gates. Thin - keep it that way. |
| `squad/__init__.py` | `SquadMember` dataclass + `build_agent()` / `build_task()` helpers. Each helper reads prose from a single-purpose `.md` file. |
| `squad/<member>/{role,goal,backstory}.md` | Three single-purpose files driving the CrewAI Agent. Edit to tune agent behaviour. |
| `squad/<member>/{description,expected_output}.md` | Two single-purpose files driving the Task description and expected output. |
| `squad/<member>/__init__.py` | Tool functions (`@tool`) + a module-level `MEMBER = SquadMember(...)` constant. |
| `tools/h1_api.py` | HackerOne REST client. Singleton: `from tools.h1_api import h1`. |
| `tools/recon/` | Recon tools: subfinder, httpx, dnsx (subdomain-takeover detection), nmap, TLS, DNS, dirfuzz, waybackurls, cert transparency, traceroute, scope guard. |
| `tools/recon/scope.py` | `filter_in_scope()` - hard scope enforcement boundary. Do not weaken. |
| `tools/recon_insights.py` | Host-annotation authoring primitives for the OSINT Analyst: HostInsight persistence, quality validation, and final consolidation of attack_graph.json + insights into recon.json. |
| `tools/pentest/` | Pentest tools: nuclei, sqlmap, CORS, SSRF, XSS, SRI, header injection, source maps, error disclosure. |
| `tools/cloud/` | Cloud/service checks: S3, Azure Blob, per-engine databases, admin panels, branded panels. |
| `tools/cloud/databases/` | Per-engine unauthenticated database checks: one file per engine. |
| `tools/triage_tools.py` | Authoring primitives for the Vulnerability Researcher: per-finding assessment / discard, quality validation, and final consolidation into verified.json. |
| `tools/report_tools.py` | Authoring primitives for the Technical Author: evidence sanitisation, draft persistence, quality validation, and final consolidation into reports.json. |
| `models/mitre/cwe.py` (`CWE`) / `tools/owasp_data.py` | CWE enrichment from the bundled MITRE corpus (by id) and the local OWASP cheat-sheet catalogue, both cited by the Vulnerability Researcher and Technical Author. |
