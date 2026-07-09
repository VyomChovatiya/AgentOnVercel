"""
Reusable indirect-prompt-injection regex detection.

This is the first-pass guard used before optional LLM classification. It is
kept dependency-light so the MCP server can run in regex-only mode.
"""

from __future__ import annotations

import re


IPI_PATTERNS = [
    (r"ignore\s+((all|the)\s+)?(previous|prior|above|all)\s+(instructions?|prompts?|tasks?|context)", "explicit_override", "BLOCK"),
    (r"disregard\s+(your|the|all)\s+(instructions?|task|system|previous|prior)", "explicit_override", "BLOCK"),
    (r"forget\s+(everything|all|your\s+previous|prior)", "explicit_override", "BLOCK"),
    (r"override\s+(your|the)\s+(instructions?|safety|previous|prior)", "explicit_override", "BLOCK"),
    (r"do\s+not\s+follow\s+(your|the|previous|prior)\s+(instructions?|task)", "explicit_override", "BLOCK"),
    (r"you\s+are\s+now\s+(a|an)\s+\w+", "role_injection", "BLOCK"),
    (r"act\s+as\s+(a|an)\s+\w+\s+(without|ignore|disregard)", "role_injection", "BLOCK"),
    (r"(new|updated|revised)\s+(system\s+)?instructions?\s*:", "role_injection", "BLOCK"),
    (r"<\|?(system|im_start|im_end)\|?>", "role_injection", "BLOCK"),
    (r"(before\s+you\s+(can|do|proceed|continue|answer|respond|complete|finish|execute|help))", "priority_hijack", "FLAG"),
    (r"(as\s+a\s+(mandatory|required|critical|urgent|important)\s+(first\s+)?(step|task|action|priority))", "priority_hijack", "FLAG"),
    (r"(important\s*:\s*(you\s+must|please|first))", "priority_hijack", "FLAG"),
    (r"\[\s*(SYSTEM|ADMIN|ROOT|OVERRIDE|PRIORITY|IMPORTANT|URGENT)\s*\]", "priority_hijack", "BLOCK"),
    (r"(mandatory|required|critical)\s+(preliminary|prerequisite|prior)\s+(step|task|action)", "priority_hijack", "FLAG"),
    (r"(use|call|invoke|execute|run)\s+the\s+\w+\s+tool", "tool_directive", "FLAG"),
    (r"(using|via|through)\s+the\s+(send_email|get_emails|update_email_status|web_search|scrape_url|local_reader)\s+(tool|function|api)", "tool_directive", "BLOCK"),
    (r"(send|forward|email|mail)\s+(all|the|my|our|their|conversation|history|context|messages?|data|contents?)", "data_exfil", "BLOCK"),
    (r"upload\s+(all|the|my|our|conversation|data|files?|contents?)", "data_exfil", "BLOCK"),
    (r"(exfiltrate|leak|expose|transmit|transfer)\s+(data|information|content|messages?|files?)", "data_exfil", "BLOCK"),
    (r"(stop|cease|halt)\s+(what\s+you\s+were\s+doing|your\s+(current\s+)?(task|work|action))", "task_redirect", "BLOCK"),
    (r"instead\s+(of\s+\w+\s+)?now\s+(do|perform|execute|call|send|delete|forward)", "task_redirect", "BLOCK"),
    (r"(your\s+(new|real|actual|true|primary)\s+(task|goal|objective|purpose|mission|job))", "task_redirect", "BLOCK"),
    (r"(switch\s+to|change\s+to|now\s+focus\s+on)\s+(a\s+(new|different))?", "task_redirect", "FLAG"),
    (r"(do\s+not|don'?t)\s+(tell|inform|mention|reveal|show|say)\s+(the\s+)?(user|human|person)", "secrecy", "BLOCK"),
    (r"(keep\s+(this|it)\s+(secret|hidden|confidential|private))", "secrecy", "BLOCK"),
    (r"without\s+(the\s+)?(user'?s?\s+)?(knowledge|awareness|permission|consent)", "secrecy", "BLOCK"),
    (r"(send|email|forward|transmit)\s+(my\s+)?(password|credentials?|token|api.?key|secret)", "credential_harvest", "BLOCK"),
    (r"(reveal|expose|share|leak)\s+(your\s+)?(system\s+prompt|instructions?|configuration)", "prompt_leak", "BLOCK"),
]


def regex_scan(content: str) -> dict:
    content = content or ""
    low = content.lower()
    matches = []

    for pattern, label, action in IPI_PATTERNS:
        match = re.search(pattern, low)
        if match:
            matches.append(
                {
                    "label": label,
                    "action": action,
                    "matched": content[max(0, match.start() - 30) : match.end() + 30].strip(),
                }
            )

    highest = (
        "BLOCK"
        if any(item["action"] == "BLOCK" for item in matches)
        else "FLAG"
        if any(item["action"] == "FLAG" for item in matches)
        else None
    )
    return {"triggered": bool(matches), "matches": matches, "highest_action": highest}


def scan(content: str, user_goal: str = "") -> dict:
    rx = regex_scan(content)

    if rx["highest_action"] == "BLOCK":
        verdict = "INJECTION"
    elif rx["highest_action"] == "FLAG":
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "verdict": verdict,
        "flagged": verdict != "CLEAN",
        "reason": rx["matches"][0]["label"] if rx["matches"] else "",
        "injected_directive": rx["matches"][0]["matched"] if rx["matches"] else "",
        "regex": rx,
    }
