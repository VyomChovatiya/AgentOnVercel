from __future__ import annotations

from mcp_checker.config import Settings
from mcp_checker.llm.anthropic import AnthropicProvider
from mcp_checker.llm.base import LLMProvider
from mcp_checker.llm.gemini import GeminiProvider
from mcp_checker.llm.openai_compatible import OpenAICompatibleProvider


def create_llm_provider(settings: Settings) -> LLMProvider | None:
    if not settings.llm_enabled:
        return None

    provider = settings.llm_provider
    if provider in {"openai", "openai_compatible", "openai-compatible"}:
        return OpenAICompatibleProvider(settings)
    if provider == "anthropic":
        return AnthropicProvider(settings)
    if provider == "gemini":
        return GeminiProvider(settings)

    raise ValueError(f"Unsupported LLM_PROVIDER: {settings.llm_provider}")
