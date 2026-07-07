from __future__ import annotations


def truncate_by_lines(content: str, max_lines: int) -> tuple[str, bool, int]:
    lines = content.splitlines()
    if len(lines) <= max_lines:
        return content, False, len(lines)
    return "\n".join(lines[:max_lines]), True, len(lines)
