"""LLM-powered endpoint detection for the OSINT Analyst."""

from __future__ import annotations

import json
import logging

from config import config
from models import Endpoint
from tools import http

logger = logging.getLogger(__name__)

# URL path segments that strongly suggest an LLM-backed endpoint.
_LLM_PATH_TOKENS = frozenset(
    {
        # Model names / providers
        "claude",
        "gpt",
        "gemini",
        "ollama",
        "groq",
        # Generic AI capability paths
        "ai",
        "llm",
        "chat",
        "ask",
        "assistant",
        "bot",
        "copilot",
        # API operation paths
        "completions",
        "generate",
        "inference",
        "predict",
        # MCP (Model Context Protocol) servers
        "mcp",
        # Vertex AI (Google Cloud)
        "vertex",
        # LangChain / LangServe / LangGraph
        "langchain",
        "langgraph",
        "runnable",
        # AWS Bedrock
        "bedrock",
    }
)

# JSON response keys present in OpenAI-compatible chat completion responses.
_OPENAI_RESPONSE_KEYS = frozenset({"choices", "prompt_tokens", "completion_tokens"})

# JSON response keys present in other LLM framework responses.
_FRAMEWORK_RESPONSE_KEYS = frozenset(
    {
        "predictions",  # Vertex AI
        "run_id",  # LangServe
        "output",  # LangChain / LangGraph
    }
)

# HTTP response headers set by common LLM API gateways.
_LLM_HEADER_TOKENS = ("x-openai-organization", "x-ratelimit-limit-requests", "openai-processing-ms")

# Phrases that appear in unguarded LLM responses but not normal web content.
_LLM_BODY_PHRASES = (
    "I'm an AI",
    "As an AI",
    "language model",
    "I cannot assist",
    "I'm sorry, but I",
)


def _has_llm_path(url: str) -> bool:
    from urllib.parse import urlparse

    segments = {s.lower() for s in urlparse(url).path.split("/") if s}
    return bool(segments & _LLM_PATH_TOKENS)


def _probe_for_llm_signals(url: str) -> bool:
    try:
        resp = http.get(  # nosemgrep
            url,
            timeout=config.recon.http_timeout,
            allow_redirects=True,
        )
    except Exception as exc:
        logger.debug("LLM probe GET failed for %s: %s", url, exc)
        return False

    for header in _LLM_HEADER_TOKENS:
        if header in resp.headers:
            return True

    if "text/event-stream" in resp.headers.get("content-type", ""):
        return True

    body = resp.text[:1000]

    for phrase in _LLM_BODY_PHRASES:
        if phrase in body:
            return True

    try:
        data = json.loads(body)
        if isinstance(data, dict):
            if (_OPENAI_RESPONSE_KEYS | _FRAMEWORK_RESPONSE_KEYS) & data.keys():
                return True
            model_val = str(data.get("model", "")).lower()
            if any(
                name in model_val
                for name in ("gpt", "claude", "gemini", "llama", "mistral", "vertex", "bedrock")
            ):
                return True
    except (json.JSONDecodeError, ValueError):
        pass

    return False


def detect_llm_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """
    Scan a list of already-probed endpoints for signals that they are backed by
    an LLM. Detected endpoints are returned with 'LLM' appended to their
    technologies list so the Penetration Tester can target them.
    """
    results: list[Endpoint] = []
    for ep in endpoints:
        if ep.status_code and ep.status_code >= 500:
            continue
        if _has_llm_path(ep.url) or _probe_for_llm_signals(ep.url):
            tagged = ep.model_copy(update={"technologies": [*ep.technologies, "LLM"]})
            results.append(tagged)
            logger.info("LLM endpoint detected: %s", ep.url)

    logger.info("LLM detection found %d endpoints", len(results))
    return results
