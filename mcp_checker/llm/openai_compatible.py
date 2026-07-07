from __future__ import annotations

import httpx

from mcp_checker.config import Settings
from mcp_checker.llm.base import LLMProvider
from mcp_checker.llm.content import truncate_by_lines
from mcp_checker.llm.json_utils import extract_json_object
from mcp_checker.safety.prompts import CLASSIFIER_SYSTEM_PROMPT
from mcp_checker.safety.schemas import SafetyAssessment


class OpenAICompatibleProvider(LLMProvider):
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
        url = f"{self.settings.llm_base_url.rstrip('/')}/chat/completions"
        payload = {
            "model": self.settings.llm_model,
            "temperature": self.settings.llm_temperature,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": CLASSIFIER_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": self._user_prompt(content, source_url, mode, rule_assessment),
                },
            ],
        }
        headers = {"Authorization": f"Bearer {self.settings.llm_api_key}"}
        async with httpx.AsyncClient(timeout=self.settings.llm_timeout_seconds) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
        data = response.json()
        text = data["choices"][0]["message"]["content"]
        assessment = SafetyAssessment.model_validate(extract_json_object(text))
        assessment.metadata["llm_provider"] = self.settings.llm_provider
        assessment.metadata["llm_model"] = self.settings.llm_model
        return assessment

    def _user_prompt(
        self,
        content: str,
        source_url: str | None,
        mode: str,
        rule_assessment: SafetyAssessment,
    ) -> str:
        truncated_content, was_truncated, total_lines = truncate_by_lines(
            content,
            self.settings.llm_max_input_lines,
        )
        return (
            f"Mode: {mode}\n"
            f"Source URL: {source_url or 'unknown'}\n"
            f"Input lines sent: {min(total_lines, self.settings.llm_max_input_lines)} of {total_lines}\n"
            f"Input truncated: {was_truncated}\n"
            f"Rule assessment: {rule_assessment.model_dump_json()}\n\n"
            "Untrusted scraped content:\n"
            f"{truncated_content}"
        )
