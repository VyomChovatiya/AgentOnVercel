"""Backward-compatible imports for the webpage Markdown scraper.

New code should import from ``mcp_checker.webpage_markdown_scraper``.
"""

from __future__ import annotations

from mcp_checker.webpage_markdown_scraper import (
    convert_html_to_markdown,
    find_and_scrape_website,
    scrape_url_as_markdown,
    search_duckduckgo_results,
)


__all__ = [
    "convert_html_to_markdown",
    "find_and_scrape_website",
    "scrape_url_as_markdown",
    "search_duckduckgo_results",
]
