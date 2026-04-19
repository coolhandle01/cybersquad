"""
config.py — Central configuration for the Bounty Squad pipeline.
Load secrets from environment variables; never hardcode credentials.
"""

import os
from dataclasses import dataclass, field


@dataclass
class H1Config:
    """HackerOne API configuration."""

    api_username: str = field(default_factory=lambda: os.environ["H1_API_USERNAME"])
    api_token: str = field(default_factory=lambda: os.environ["H1_API_TOKEN"])
    base_url: str = "https://api.hackerone.com/v1"
    # FIX: use default_factory so os.getenv is called at instantiation time,
    # not at class-definition time — allows monkeypatch to work in tests
    min_bounty_threshold: int = field(
        default_factory=lambda: int(os.getenv("H1_MIN_BOUNTY", "500"))
    )
    max_programmes: int = field(default_factory=lambda: int(os.getenv("H1_MAX_PROGRAMMES", "10")))


@dataclass
class LLMConfig:
    """LLM / CrewAI configuration."""

    model: str = field(
        default_factory=lambda: os.getenv("CREWAI_MODEL", "claude-sonnet-4-20250514")
    )
    temperature: float = field(
        default_factory=lambda: float(os.getenv("CREWAI_TEMPERATURE", "0.2"))
    )
    max_tokens: int = field(default_factory=lambda: int(os.getenv("CREWAI_MAX_TOKENS", "4096")))


@dataclass
class ReconConfig:
    """Tuning parameters for the OSINT & recon phase."""

    wordlist_path: str = field(
        default_factory=lambda: os.getenv(
            "RECON_WORDLIST",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        )
    )
    dns_resolvers: list[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    http_timeout: int = field(default_factory=lambda: int(os.getenv("RECON_HTTP_TIMEOUT", "10")))
    max_subdomains: int = field(
        default_factory=lambda: int(os.getenv("RECON_MAX_SUBDOMAINS", "200"))
    )


@dataclass
class ScanConfig:
    """Tuning parameters for the penetration testing phase."""

    nuclei_templates_path: str = field(
        default_factory=lambda: os.getenv("NUCLEI_TEMPLATES", "~/.local/nuclei-templates")
    )
    nuclei_rate_limit: int = field(
        default_factory=lambda: int(os.getenv("NUCLEI_RATE_LIMIT", "10"))
    )
    sqlmap_level: int = field(default_factory=lambda: int(os.getenv("SQLMAP_LEVEL", "2")))
    sqlmap_risk: int = field(default_factory=lambda: int(os.getenv("SQLMAP_RISK", "1")))
    sqlmap_output_dir: str = field(
        default_factory=lambda: os.getenv("SQLMAP_OUTPUT_DIR", "/tmp/sqlmap-output")  # nosec B108  # noqa: S108
    )
    min_severity: str = field(default_factory=lambda: os.getenv("MIN_SEVERITY", "medium"))
    request_delay: float = field(default_factory=lambda: float(os.getenv("SCAN_DELAY", "0.5")))


@dataclass
class AppConfig:
    """Top-level application config — compose all sub-configs here."""

    h1: H1Config = field(default_factory=H1Config)
    llm: LLMConfig = field(default_factory=LLMConfig)
    recon: ReconConfig = field(default_factory=ReconConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    reports_dir: str = field(default_factory=lambda: os.getenv("REPORTS_DIR", "./reports"))
    verbose: bool = field(default_factory=lambda: os.getenv("VERBOSE", "false").lower() == "true")


# Singleton — import this everywhere rather than re-instantiating
config = AppConfig()
