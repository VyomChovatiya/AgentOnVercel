from mcp_checker.llm.content import truncate_by_lines


def test_truncate_by_lines_keeps_content_under_limit():
    content = "\n".join(f"line {index}" for index in range(5))

    result, was_truncated, total_lines = truncate_by_lines(content, 3)

    assert result == "line 0\nline 1\nline 2"
    assert was_truncated is True
    assert total_lines == 5


def test_truncate_by_lines_leaves_short_content_unchanged():
    content = "line 1\nline 2"

    result, was_truncated, total_lines = truncate_by_lines(content, 2500)

    assert result == content
    assert was_truncated is False
    assert total_lines == 2
