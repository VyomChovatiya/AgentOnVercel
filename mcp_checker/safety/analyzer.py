from __future__ import annotations

from mcp_checker.llm.base import LLMProvider
from mcp_checker.safety.guard_core import scan as regex_guard_scan
from mcp_checker.safety.rules import find_rule_evidence
from mcp_checker.safety.schemas import EvidenceItem, RiskLevel, SafetyAssessment, SafetyCategory
from mcp_checker.safety.scoring import score_evidence


GUARD_CATEGORY_BY_LABEL = {
    "credential_harvest": SafetyCategory.credential_exfiltration,
    "data_exfil": SafetyCategory.credential_exfiltration,
    "prompt_leak": SafetyCategory.system_prompt_extraction,
    "tool_directive": SafetyCategory.tool_abuse,
}


class SafetyAnalyzer:
    def __init__(
        self,
        llm_provider: LLMProvider | None = None,
        default_mode: str = "balanced",
        llm_requested: bool | None = None,
    ):
        self.llm_provider = llm_provider
        self.default_mode = default_mode
        self.llm_requested = llm_provider is not None if llm_requested is None else llm_requested

    async def analyze(
        self,
        content: str,
        source_url: str | None = None,
        mode: str | None = None,
    ) -> SafetyAssessment:
        selected_mode = (mode or self.default_mode or "balanced").lower()
        regex_result = regex_guard_scan(content)
        rule_evidence = self._evidence_from_regex(regex_result) + find_rule_evidence(content)
        score, risk_level = score_evidence(rule_evidence, selected_mode)
        rule_assessment = self._assessment_from_rules(
            regex_result,
            rule_evidence,
            score,
            risk_level,
            source_url,
            selected_mode,
        )

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
            rule_assessment.metadata["llm"] = {
                "enabled": True,
                "configured": True,
                "used": False,
                "error": str(exc),
                "assessment": None,
            }
            return rule_assessment

        return self._merge(rule_assessment, llm_assessment)

    def _evidence_from_regex(self, regex_result: dict) -> list[EvidenceItem]:
        evidence = []
        for item in regex_result["regex"]["matches"]:
            category = GUARD_CATEGORY_BY_LABEL.get(item["label"], SafetyCategory.prompt_injection)
            weight = 10 if item["action"] == "BLOCK" else 6
            evidence.append(EvidenceItem(
                category=category, excerpt=item["matched"], weight=weight,
                source=f"regex:{item['label']}",
            ))
        return evidence

    def _assessment_from_rules(
        self,
        regex_result: dict,
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
            evidence_details=list(rule_evidence),
            recommended_action=action,
            metadata={
                "source_url": source_url,
                "mode": mode,
                "rule_score": score,
                "regex": regex_result,
                "llm": {
                    "enabled": self.llm_requested,
                    "configured": self.llm_provider is not None,
                    "used": False,
                    "error": None
                    if self.llm_provider is not None or not self.llm_requested
                    else "LLM mode was requested, but no provider was configured. Set LLM_API_KEY or run with --no-llm.",
                    "assessment": None,
                },
                "llm_used": False,
            },
        )

    def _merge(self, rules: SafetyAssessment, llm: SafetyAssessment) -> SafetyAssessment:
        levels = list(RiskLevel)
        risk_level = max(rules.risk_level, llm.risk_level, key=levels.index)
        categories = sorted(set(rules.categories + llm.categories), key=lambda item: item.value)
        evidence = (rules.evidence + llm.evidence)[:12]
        # Structured proof: keep the rule hits (already EvidenceItem) and turn each
        # LLM-flagged span into one too, so the caller sees the offending text + why.
        llm_weight = {"safe": 2, "low": 4, "medium": 6, "high": 8, "critical": 10}.get(
            llm.risk_level.value, 6)
        llm_category = llm.categories[0] if llm.categories else SafetyCategory.prompt_injection
        llm_details = [
            EvidenceItem(category=llm_category, excerpt=str(ex)[:240], weight=llm_weight, source="llm")
            for ex in llm.evidence
        ]
        evidence_details = (list(rules.evidence_details) + llm_details)[:12]
        safe = risk_level in {RiskLevel.safe, RiskLevel.low} and rules.safe and llm.safe
        metadata = {
            **rules.metadata,
            "llm": {
                "enabled": True,
                "configured": True,
                "used": True,
                "error": None,
                "assessment": llm.model_dump(mode="json"),
            },
            "llm_used": True,
        }
        metadata.update({key: value for key, value in llm.metadata.items() if key.startswith("llm_")})

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
            evidence_details=evidence_details,
            recommended_action=action,
            metadata=metadata,
        )
