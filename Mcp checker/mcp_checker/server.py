from __future__ import annotations

from typing import Literal

from fastmcp import FastMCP

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
    content: str,
    source_url: str | None = None,
    mode: Literal["strict", "balanced", "lenient"] | None = None,
) -> dict:
    """Classify scraped content safety before an AI agent consumes it."""
    assessment: SafetyAssessment = await analyzer.analyze(
        content=content,
        source_url=source_url,
        mode=mode,
    )
    return assessment.model_dump(mode="json")


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
