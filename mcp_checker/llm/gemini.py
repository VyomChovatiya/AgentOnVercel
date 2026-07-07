from __future__ import annotations

import httpx

from mcp_checker.config import Settings
from mcp_checker.llm.base import LLMProvider
from mcp_checker.llm.content import truncate_by_lines
from mcp_checker.llm.json_utils import extract_json_object
from mcp_checker.safety.prompts import CLASSIFIER_SYSTEM_PROMPT
from mcp_checker.safety.schemas import SafetyAssessment


class GeminiProvider(LLMProvider):
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
        truncated_content, was_truncated, total_lines = truncate_by_lines(
            content,
            self.settings.llm_max_input_lines,
        )
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.settings.llm_model}:generateContent?key={self.settings.llm_api_key}"
        )
        prompt = (
            f"{CLASSIFIER_SYSTEM_PROMPT}\n\n"
            f"Mode: {mode}\nSource URL: {source_url or 'unknown'}\n"
            f"Input lines sent: {min(total_lines, self.settings.llm_max_input_lines)} of {total_lines}\n"
            f"Input truncated: {was_truncated}\n"
            f"Rule assessment: {rule_assessment.model_dump_json()}\n\n"
            f"Untrusted scraped content:\n{truncated_content}"
        )
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self.settings.llm_temperature,
                "responseMimeType": "application/json",
            },
        }
        async with httpx.AsyncClient(timeout=self.settings.llm_timeout_seconds) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
        data = response.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        assessment = SafetyAssessment.model_validate(extract_json_object(text))
        assessment.metadata["llm_provider"] = self.settings.llm_provider
        assessment.metadata["llm_model"] = self.settings.llm_model
        return assessment
