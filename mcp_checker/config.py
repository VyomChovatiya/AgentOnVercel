from __future__ import annotations

import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv() -> None:
        return None


@dataclass(frozen=True)
class Settings:
    llm_enabled: bool
    llm_provider: str
    llm_api_key: str | None
    llm_model: str
    llm_base_url: str | None
    llm_timeout_seconds: float
    llm_temperature: float
    llm_max_input_lines: int
    safety_mode: str
    mcp_transport: str
    mcp_host: str
    mcp_port: int


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_settings() -> Settings:
    load_dotenv()
    return Settings(
        llm_enabled=_bool_env("LLM_ENABLED", False),
        llm_provider=os.getenv("LLM_PROVIDER", "openai_compatible").strip().lower(),
        llm_api_key=os.getenv("LLM_API_KEY") or None,
        llm_model=os.getenv("LLM_MODEL", "gpt-4.1-mini"),
        llm_base_url=os.getenv("LLM_BASE_URL") or "https://api.openai.com/v1",
        llm_timeout_seconds=float(os.getenv("LLM_TIMEOUT_SECONDS", "20")),
        llm_temperature=float(os.getenv("LLM_TEMPERATURE", "0")),
        llm_max_input_lines=int(os.getenv("LLM_MAX_INPUT_LINES", "2500")),
        safety_mode=os.getenv("SAFETY_MODE", "balanced").strip().lower(),
        mcp_transport=os.getenv("MCP_TRANSPORT", "stdio").strip().lower(),
        mcp_host=os.getenv("MCP_HOST", "127.0.0.1").strip(),
        mcp_port=int(os.getenv("MCP_PORT", "8000")),
    )
