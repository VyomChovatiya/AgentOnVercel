from __future__ import annotations

from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import Field

from mcp_checker.config import load_settings
from mcp_checker.llm.factory import create_llm_provider
from mcp_checker.safety.analyzer import SafetyAnalyzer
from mcp_checker.safety.schemas import SafetyAssessment


settings = load_settings()
analyzer = SafetyAnalyzer(
    llm_provider=create_llm_provider(settings),
    default_mode=settings.safety_mode,
)
mcp = FastMCP("mcp-content-safety-checker")


@mcp.tool()
async def analyze_scraped_content(
    content: Annotated[
        str,
        Field(
            description=(
                "Raw scraped page content to inspect. Pass the untrusted text, HTML, "
                "markdown, or extracted webpage body here. Do not summarize it first."
            ),
            min_length=1,
        ),
    ],
    source_url: Annotated[
        str | None,
        Field(
            description=(
                "Optional URL where the content came from. Use null or omit this field "
                "when the source is unknown."
            ),
        ),
    ] = None,
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
    """Analyze scraped content and decide if it is safe for an AI agent.

    Use this tool before placing webpage, document, or scraped text into an
    agent's context. The input must be a JSON object with:

    - content: required string containing the scraped content to classify.
    - source_url: optional string or null with the original URL.
    - mode: optional string, one of "strict", "balanced", or "lenient".

    The tool returns a JSON safety assessment with safe, risk_level, categories,
    summary, evidence, recommended_action, and metadata.
    """
    assessment: SafetyAssessment = await analyzer.analyze(
        content=content,
        source_url=source_url,
        mode=mode,
    )
    return assessment.model_dump(mode="json")


def main() -> None:
    if settings.mcp_transport == "stdio":
        mcp.run(transport="stdio")
        return

    mcp.run(
        transport=settings.mcp_transport,
        host=settings.mcp_host,
        port=settings.mcp_port,
    )


if __name__ == "__main__":
    main()
