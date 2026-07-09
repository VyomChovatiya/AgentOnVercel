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


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Find a website and scrape its page content as Markdown.")
    parser.add_argument("website_or_url", help="Website name, search query, or URL to scrape.")
    parser.add_argument("--max-results", type=int, default=5)
    args = parser.parse_args()

    result = find_and_scrape_website(args.website_or_url, max_results=args.max_results)
    print(json.dumps(result, indent=2, ensure_ascii=False))
