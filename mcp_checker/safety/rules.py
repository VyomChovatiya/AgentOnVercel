from __future__ import annotations

import re

from mcp_checker.safety.schemas import EvidenceItem, SafetyCategory


Rule = tuple[SafetyCategory, int, re.Pattern[str]]


RULES: list[Rule] = [
    (
        SafetyCategory.prompt_injection,
        8,
        re.compile(r"\b(ignore|forget|discard)\b.{0,80}\b(previous|prior|above|system|developer)\b.{0,80}\b(instructions?|rules?|prompt)\b", re.I | re.S),
    ),
    (
        SafetyCategory.prompt_injection,
        7,
        re.compile(r"\byou are now\b|\bnew instructions?\b|\boverride\b.{0,40}\binstructions?\b", re.I | re.S),
    ),
    (
        SafetyCategory.system_prompt_extraction,
        8,
        re.compile(r"\b(system prompt|developer message|hidden instructions?|initial instructions?)\b", re.I),
    ),
    (
        SafetyCategory.credential_exfiltration,
        10,
        re.compile(r"\b(api[_ -]?key|access token|secret key|password|credentials?|env(?:ironment)? variables?)\b", re.I),
    ),
    (
        SafetyCategory.tool_abuse,
        8,
        re.compile(r"\b(run|execute|call|invoke)\b.{0,60}\b(shell|terminal|powershell|bash|cmd|tool|function|api)\b", re.I | re.S),
    ),
    (
        SafetyCategory.tool_abuse,
        9,
        re.compile(r"\b(rm\s+-rf|del\s+/f|format\s+[a-z]:|curl\s+.+\|\s*(sh|bash)|wget\s+.+\|\s*(sh|bash))\b", re.I),
    ),
    (
        SafetyCategory.malware_or_phishing,
        7,
        re.compile(r"\b(phishing|malware|payload|keylogger|reverse shell|credential harvester)\b", re.I),
    ),
    (
        SafetyCategory.unsafe_instructions,
        6,
        re.compile(r"\b(make|build|create|synthesize)\b.{0,80}\b(explosive|poison|weapon|malware)\b", re.I | re.S),
    ),
    (
        SafetyCategory.sensitive_personal_data,
        5,
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\b(?:\d[ -]*?){13,16}\b"),
    ),
    (
        SafetyCategory.spam_or_manipulative_content,
        4,
        re.compile(r"\b(click here now|limited time|guaranteed profit|act immediately)\b", re.I),
    ),
    (
        SafetyCategory.suspicious_encoding,
        6,
        re.compile(r"\b(?:[A-Za-z0-9+/]{80,}={0,2}|[A-Fa-f0-9]{96,})\b"),
    ),
]


def find_rule_evidence(content: str, max_items: int = 12) -> list[EvidenceItem]:
    evidence: list[EvidenceItem] = []
    for category, weight, pattern in RULES:
        for match in pattern.finditer(content):
            excerpt = _compact(content[max(0, match.start() - 60) : match.end() + 60])
            evidence.append(EvidenceItem(category=category, excerpt=excerpt, weight=weight))
            if len(evidence) >= max_items:
                return evidence
    return evidence


def _compact(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()
