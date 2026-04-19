"""
agents.py — Agent definitions for the Bounty Squad.

Each agent is a CrewAI Agent with a professional role, a focused goal,
and a curated backstory that shapes its LLM persona.
"""

from __future__ import annotations

from crewai import Agent
from crewai_tools import tool
from langchain_anthropic import ChatAnthropic

from config import config
from tools.h1_api import h1
from tools.recon_tools import run_recon
from tools.report_tools import save_report
from tools.vuln_tools import run_pentest, triage_findings


@tool("List HackerOne Programmes")
def list_programmes_tool(page_size: int = 25) -> list[dict]:
    """Fetch and return a list of active HackerOne bug bounty programmes."""
    return h1.list_programmes(page_size=page_size)


@tool("Get Programme Scope")
def get_scope_tool(handle: str) -> dict:
    """Fetch the structured in-scope and out-of-scope assets for a programme."""
    policy = h1.get_programme_policy(handle)
    scope = h1.get_structured_scope(handle)
    return {"policy": policy, "scope": scope}


@tool("Run Recon")
def recon_tool(programme_handle: str) -> dict:
    """
    Run full OSINT recon (subdomain enumeration, HTTP probing, port scanning)
    against the in-scope assets of the given programme handle.
    Returns a serialised ReconResult.
    """
    policy = h1.get_programme_policy(programme_handle)
    scope = h1.get_structured_scope(programme_handle)
    programme = h1.parse_programme(policy["data"], scope)
    result = run_recon(programme)
    return result.model_dump()  # type: ignore[no-any-return]


@tool("Run Penetration Test")
def pentest_tool(recon_result_json: str) -> list[dict]:
    """
    Run nuclei, sqlmap, and custom checks against a serialised ReconResult.
    Returns a list of raw findings as dicts.
    """
    from models import ReconResult

    recon = ReconResult.model_validate_json(recon_result_json)
    findings = run_pentest(recon)
    return [f.model_dump() for f in findings]


@tool("Triage Findings")
def triage_tool(raw_findings_json: str, programme_handle: str) -> list[dict]:
    """
    Triage raw findings against programme scope and severity floor.
    Returns verified vulnerabilities as dicts.
    """
    import json

    from models import RawFinding

    raw = [RawFinding.model_validate(f) for f in json.loads(raw_findings_json)]
    policy = h1.get_programme_policy(programme_handle)
    scope = h1.get_structured_scope(programme_handle)
    programme = h1.parse_programme(policy["data"], scope)
    verified = triage_findings(raw, programme)
    return [v.model_dump() for v in verified]


@tool("Submit Report")
def submit_report_tool(report_json: str) -> dict:
    """Submit a serialised DisclosureReport to HackerOne."""
    from models import DisclosureReport

    report = DisclosureReport.model_validate_json(report_json)
    save_report(report)
    result = h1.submit_report(report)
    return result.model_dump()  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Agent definitions
# ---------------------------------------------------------------------------


def build_agents(verbose: bool = False) -> dict[str, Agent]:
    """
    Instantiate and return all six squad members keyed by role slug.
    """
    # FIX: temperature/max_tokens were silently ignored when passing llm as a
    # model-name string. ChatAnthropic is explicitly constructed so all LLM
    # config is honoured.
    llm = ChatAnthropic(
        model=config.llm.model,
        temperature=config.llm.temperature,
        max_tokens=config.llm.max_tokens,
    )

    llm_config = {"llm": llm, "verbose": verbose}

    programme_manager = Agent(
        role="Programme Manager",
        goal=(
            "Identify the highest-value HackerOne bug bounty programmes — "
            "maximising expected payout relative to attack surface complexity — "
            "whilst rigorously verifying that automated scanning is permitted."
        ),
        backstory=(
            "You are a seasoned security programme manager with a decade of "
            "experience prioritising vulnerability disclosure efforts across "
            "Fortune 500 clients. You have an encyclopaedic knowledge of "
            "HackerOne programme policies and a sharp eye for ROI. You never "
            "authorise work against a programme that prohibits automated tools."
        ),
        tools=[list_programmes_tool, get_scope_tool],
        allow_delegation=False,
        **llm_config,
    )

    osint_analyst = Agent(
        role="OSINT Analyst",
        goal=(
            "Build a comprehensive, in-scope attack surface map for the target "
            "programme — subdomains, live endpoints, open ports, and technology "
            "stack — using only passive and semi-passive reconnaissance techniques."
        ),
        backstory=(
            "You are an OSINT specialist who has mapped the attack surfaces of "
            "hundreds of organisations. You are meticulous about staying within "
            "authorised scope, and you document everything with the precision of "
            "a cartographer. You know every subdomain enumeration trick in the book."
        ),
        tools=[recon_tool],
        allow_delegation=False,
        **llm_config,
    )

    penetration_tester = Agent(
        role="Penetration Tester",
        goal=(
            "Execute targeted vulnerability scans across the discovered attack "
            "surface, employing nuclei, sqlmap, and bespoke checks to surface "
            "exploitable weaknesses whilst respecting rate limits and scope boundaries."
        ),
        backstory=(
            "You are an offensive security engineer with certifications in OSCP, "
            "CREST CRT, and eWPT. You approach every engagement methodically — "
            "running the right tool for the right target — and you never fire a "
            "payload at an asset that is out of scope. You are efficient, precise, "
            "and deeply familiar with the OWASP Top 10."
        ),
        tools=[pentest_tool],
        allow_delegation=False,
        **llm_config,
    )

    vulnerability_researcher = Agent(
        role="Vulnerability Researcher",
        goal=(
            "Triage all raw scanner output to eliminate false positives, confirm "
            "exploitability, assign accurate CVSS scores, and produce clean, "
            "scope-validated findings ready for professional documentation."
        ),
        backstory=(
            "You are a vulnerability researcher who has published CVEs and "
            "presented at DEF CON. You have an instinct for separating genuine "
            "security issues from scanner noise, and your CVSS scoring is trusted "
            "by vendors worldwide. You refuse to forward a finding to reporting "
            "unless you are personally confident it is real and in scope."
        ),
        tools=[triage_tool],
        allow_delegation=False,
        **llm_config,
    )

    technical_author = Agent(
        role="Technical Author",
        goal=(
            "Transform verified vulnerability data into clear, compelling, and "
            "complete H1-format disclosure reports — with precise reproduction "
            "steps, accurate impact statements, and actionable remediation advice."
        ),
        backstory=(
            "You are a technical author who spent five years writing security "
            "advisories for a national CERT before moving into bug bounty. "
            "Your reports are legendary for their clarity: even a junior developer "
            "can follow your reproduction steps, and your impact statements have "
            "never been disputed by a programme triage team. You take pride in "
            "reports that get triaged first time, every time."
        ),
        tools=[],
        allow_delegation=False,
        **llm_config,
    )

    disclosure_coordinator = Agent(
        role="Disclosure Coordinator",
        goal=(
            "Submit finalised disclosure reports to HackerOne via the API, "
            "confirm successful receipt, and log submission metadata for "
            "tracking and follow-up."
        ),
        backstory=(
            "You are a disclosure coordinator who has managed the responsible "
            "disclosure lifecycle for over 300 vulnerabilities. You are calm "
            "under pressure, precise with API payloads, and you maintain "
            "meticulous records of every submission status. Nothing slips "
            "through your process."
        ),
        tools=[submit_report_tool],
        allow_delegation=False,
        **llm_config,
    )

    return {
        "programme_manager": programme_manager,
        "osint_analyst": osint_analyst,
        "penetration_tester": penetration_tester,
        "vulnerability_researcher": vulnerability_researcher,
        "technical_author": technical_author,
        "disclosure_coordinator": disclosure_coordinator,
    }
