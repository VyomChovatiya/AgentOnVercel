from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    safe = "safe"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class SafetyCategory(str, Enum):
    prompt_injection = "prompt_injection"
    system_prompt_extraction = "system_prompt_extraction"
    credential_exfiltration = "credential_exfiltration"
    tool_abuse = "tool_abuse"
    malware_or_phishing = "malware_or_phishing"
    unsafe_instructions = "unsafe_instructions"
    sensitive_personal_data = "sensitive_personal_data"
    spam_or_manipulative_content = "spam_or_manipulative_content"
    suspicious_encoding = "suspicious_encoding"


class EvidenceItem(BaseModel):
    category: SafetyCategory
    excerpt: str = Field(max_length=240)
    weight: int = Field(ge=1, le=10)


class SafetyAssessment(BaseModel):
    safe: bool
    risk_level: RiskLevel
    categories: list[SafetyCategory] = Field(default_factory=list)
    summary: str
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str
    metadata: dict[str, Any] = Field(default_factory=dict)
