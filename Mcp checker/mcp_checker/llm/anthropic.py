from __future__ import annotations

import httpx

from mcp_checker.config import Settings
from mcp_checker.llm.base import LLMProvider
from mcp_checker.llm.json_utils import extract_json_object
from mcp_checker.safety.prompts import CLASSIFIER_SYSTEM_PROMPT
from mcp_checker.safety.schemas import SafetyAssessment


class AnthropicProvider(LLMProvider):
    def __init__(self, settings: Settings):
        if not settings.llm_api_key:
            raise ValueError("LLM_API_KEY is required when LLM_ENABLED=true.")
        self.settings = settings

    async def classify(
        self,
        content: str,
        source_url: str | None,
        mode: str,
        rule_assessment: SafetyAssessment,
    ) -> SafetyAssessment:
        payload = {
            "model": self.settings.llm_model,
            "max_tokens": 1000,
            "temperature": self.settings.llm_temperature,
            "system": CLASSIFIER_SYSTEM_PROMPT,
            "messages": [
                {
                    "role": "user",
                    "content": (
                        f"Mode: {mode}\nSource URL: {source_url or 'unknown'}\n"
                        f"Rule assessment: {rule_assessment.model_dump_json()}\n\n"
                        f"Untrusted scraped content:\n{content[:12000]}"
                    ),
                }
            ],
        }
        headers = {
            "x-api-key": self.settings.llm_api_key or "",
            "anthropic-version": "2023-06-01",
        }
        async with httpx.AsyncClient(timeout=self.settings.llm_timeout_seconds) as client:
            response = await client.post("https://api.anthropic.com/v1/messages", json=payload, headers=headers)
            response.raise_for_status()
        data = response.json()
        text = "".join(block.get("text", "") for block in data.get("content", []))
        assessment = SafetyAssessment.model_validate(extract_json_object(text))
        assessment.metadata["llm_provider"] = self.settings.llm_provider
        assessment.metadata["llm_model"] = self.settings.llm_model
        return assessment
