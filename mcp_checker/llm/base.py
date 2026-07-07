from __future__ import annotations

from abc import ABC, abstractmethod

from mcp_checker.safety.schemas import SafetyAssessment


class LLMProvider(ABC):
    @abstractmethod
    async def classify(
        self,
        content: str,
        source_url: str | None,
        mode: str,
        rule_assessment: SafetyAssessment,
    ) -> SafetyAssessment:
        """Classify scraped content using a provider-specific API."""
