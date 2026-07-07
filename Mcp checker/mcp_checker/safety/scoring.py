from __future__ import annotations

from collections.abc import Iterable

from mcp_checker.safety.schemas import EvidenceItem, RiskLevel


MODE_MULTIPLIER = {
    "strict": 1.25,
    "balanced": 1.0,
    "lenient": 0.8,
}


def score_evidence(evidence: Iterable[EvidenceItem], mode: str) -> tuple[int, RiskLevel]:
    raw_score = sum(item.weight for item in evidence)
    score = round(raw_score * MODE_MULTIPLIER.get(mode, 1.0))

    if score >= 20:
        return score, RiskLevel.critical
    if score >= 12:
        return score, RiskLevel.high
    if score >= 7:
        return score, RiskLevel.medium
    if score >= 3:
        return score, RiskLevel.low
    return score, RiskLevel.safe
