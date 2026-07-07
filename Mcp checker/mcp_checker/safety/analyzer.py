from __future__ import annotations

from mcp_checker.llm.base import LLMProvider
from mcp_checker.safety.rules import find_rule_evidence
from mcp_checker.safety.schemas import RiskLevel, SafetyAssessment, SafetyCategory
from mcp_checker.safety.scoring import score_evidence


class SafetyAnalyzer:
    def __init__(self, llm_provider: LLMProvider | None = None, default_mode: str = "balanced"):
        self.llm_provider = llm_provider
        self.default_mode = default_mode

    async def analyze(
        self,
        content: str,
        source_url: str | None = None,
        mode: str | None = None,
    ) -> SafetyAssessment:
        selected_mode = (mode or self.default_mode or "balanced").lower()
        rule_evidence = find_rule_evidence(content)
        score, risk_level = score_evidence(rule_evidence, selected_mode)
        rule_assessment = self._assessment_from_rules(rule_evidence, score, risk_level, source_url, selected_mode)

        if self.llm_provider is None:
            return rule_assessment

        try:
            llm_assessment = await self.llm_provider.classify(
                content=content,
                source_url=source_url,
                mode=selected_mode,
                rule_assessment=rule_assessment,
            )
        except Exception as exc:
            rule_assessment.metadata["llm_error"] = str(exc)
            return rule_assessment

        return self._merge(rule_assessment, llm_assessment)

    def _assessment_from_rules(
        self,
        rule_evidence,
        score: int,
        risk_level: RiskLevel,
        source_url: str | None,
        mode: str,
    ) -> SafetyAssessment:
        categories = sorted({item.category for item in rule_evidence}, key=lambda item: item.value)
        safe = risk_level in {RiskLevel.safe, RiskLevel.low}
        if not rule_evidence:
            summary = "No obvious prompt-injection, exfiltration, or tool-abuse patterns were detected."
            action = "Content can be used as untrusted context with normal safeguards."
        elif safe:
            summary = "Low-risk signals were detected, but no strong agent-targeting attack pattern was found."
            action = "Use as untrusted context and avoid treating page text as instructions."
        else:
            summary = "Content contains patterns that may manipulate an AI agent or request sensitive actions."
            action = "Do not pass this content directly to an agent without review or sanitization."

        return SafetyAssessment(
            safe=safe,
            risk_level=risk_level,
            categories=categories,
            summary=summary,
            evidence=[item.excerpt for item in rule_evidence],
            recommended_action=action,
            metadata={
                "source_url": source_url,
                "mode": mode,
                "rule_score": score,
                "llm_used": False,
            },
        )

    def _merge(self, rules: SafetyAssessment, llm: SafetyAssessment) -> SafetyAssessment:
        levels = list(RiskLevel)
        risk_level = max(rules.risk_level, llm.risk_level, key=levels.index)
        categories = sorted(set(rules.categories + llm.categories), key=lambda item: item.value)
        evidence = (rules.evidence + llm.evidence)[:12]
        safe = risk_level in {RiskLevel.safe, RiskLevel.low} and rules.safe and llm.safe
        metadata = {**rules.metadata, **llm.metadata, "llm_used": True}

        summary = llm.summary if llm.risk_level.value != "safe" else rules.summary
        action = (
            "Do not pass this content directly to an agent without review or sanitization."
            if not safe
            else "Content can be used as untrusted context with normal safeguards."
        )
        return SafetyAssessment(
            safe=safe,
            risk_level=risk_level,
            categories=categories,
            summary=summary,
            evidence=evidence,
            recommended_action=action,
            metadata=metadata,
        )
