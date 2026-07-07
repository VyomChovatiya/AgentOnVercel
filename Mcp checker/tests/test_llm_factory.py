from mcp_checker.config import Settings
from mcp_checker.llm.factory import create_llm_provider
from mcp_checker.llm.openai_compatible import OpenAICompatibleProvider


def test_factory_returns_none_when_disabled():
    settings = Settings(False, "openai_compatible", None, "model", None, 20, 0, "balanced")

    assert create_llm_provider(settings) is None


def test_factory_returns_openai_compatible_provider():
    settings = Settings(True, "openai_compatible", "key", "model", "https://example.com/v1", 20, 0, "balanced")

    assert isinstance(create_llm_provider(settings), OpenAICompatibleProvider)
