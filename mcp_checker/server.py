from __future__ import annotations

import argparse
from dataclasses import replace
from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import Field

from mcp_checker.config import Settings
from mcp_checker.config import load_settings
from mcp_checker.llm.factory import create_llm_provider
from mcp_checker.webpage_markdown_scraper import find_and_scrape_website
from mcp_checker.safety.analyzer import SafetyAnalyzer
from mcp_checker.safety.schemas import SafetyAssessment


settings = load_settings()
analyzer = SafetyAnalyzer(
    llm_provider=create_llm_provider(settings),
    default_mode=settings.safety_mode,
    llm_requested=settings.llm_enabled,
)
mcp = FastMCP("webpage-safety-scanner")


def configure_runtime(runtime_settings: Settings) -> None:
    global analyzer, settings
    settings = runtime_settings
    analyzer = SafetyAnalyzer(
        llm_provider=create_llm_provider(settings),
        default_mode=settings.safety_mode,
        llm_requested=settings.llm_enabled,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the MCP webpage safety scanner.")
    llm_group = parser.add_mutually_exclusive_group()
    llm_group.add_argument("--llm", action="store_true", help="Enable optional LLM classification.")
    llm_group.add_argument("--no-llm", action="store_true", help="Run regex/rule-only detection.")
    return parser.parse_args()


@mcp.tool()
async def check_website_safety(
    website_or_url: Annotated[
        str,
        Field(
            description=(
                "Website name, search query, or URL to inspect. The server searches "
                "with DuckDuckGo when needed, scrapes the selected page as Markdown, "
                "then checks it for prompt-injection and safety risks."
            ),
            min_length=1,
        ),
    ],
    mode: Annotated[
        Literal["strict", "balanced", "lenient"] | None,
        Field(
            description=(
                "Optional sensitivity mode. Use strict for high-risk agents with tools "
                "or private data, balanced for normal use, and lenient for noisy or "
                "educational content. If omitted, the server uses SAFETY_MODE from .env."
            ),
        ),
    ] = None,
) -> dict:
    """Search/scrape a website and decide if it is safe for an AI agent.

    Use this tool before placing webpage or scraped text into an
    agent's context. The input must be a JSON object with:

    - website_or_url: required website name, search query, or URL to scrape.
    - mode: optional string, one of "strict", "balanced", or "lenient".

    The tool returns a JSON safety assessment with scrape metadata plus regex
    and optional LLM results.
    """
    try:
        scrape_result = find_and_scrape_website(website_or_url)
    except Exception as exc:
        return {
            "safe": False,
            "risk_level": "high",
            "categories": ["unsafe_instructions"],
            "summary": "The website could not be searched or scraped for safety analysis.",
            "evidence": [str(exc)],
            "recommended_action": "Do not pass this website content to an agent until scraping succeeds.",
            "metadata": {
                "website_or_url": website_or_url,
                "scrape_error": str(exc),
                "llm_used": False,
            },
        }

    assessment: SafetyAssessment = await analyzer.analyze(
        content=scrape_result["markdown"],
        source_url=scrape_result["selected_url"],
        mode=mode,
    )
    result = assessment.model_dump(mode="json")
    result["metadata"]["website_or_url"] = website_or_url
    result["metadata"]["scrape"] = {
        "selected_url": scrape_result["selected_url"],
        "title": scrape_result["title"],
        "markdown_characters": len(scrape_result["markdown"]),
        "search_results": scrape_result["search_results"],
    }
    return result


def main() -> None:
    args = parse_args()
    runtime_settings = settings
    if args.llm:
        runtime_settings = replace(settings, llm_enabled=True)
    elif args.no_llm:
        runtime_settings = replace(settings, llm_enabled=False)
    configure_runtime(runtime_settings)

    if settings.mcp_transport == "stdio":
        mcp.run(transport="stdio")
        return

    mcp.run(
        transport=settings.mcp_transport,
        host=settings.mcp_host,
        port=settings.mcp_port,
        host_origin_protection=settings.mcp_host_origin_protection,
    )


if __name__ == "__main__":
    main()
