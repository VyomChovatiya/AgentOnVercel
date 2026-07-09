"""Quick standalone runner — scrape + safety-analyze a URL with the LLM ON,
without needing an MCP client. Usage:
    .\.venv\Scripts\python.exe run_scan.py [url_or_query]
"""
import asyncio, json, sys
from dataclasses import replace

from mcp_checker import server
from mcp_checker.config import load_settings
from mcp_checker.webpage_markdown_scraper import find_and_scrape_website

URL = sys.argv[1] if len(sys.argv) > 1 else \
    "https://nextgen-products.onrender.com/p/iphone-17-verge-review"


async def main():
    # rebuild the analyzer with the LLM classifier enabled (same as --llm)
    server.configure_runtime(replace(load_settings(), llm_enabled=True))
    scrape = find_and_scrape_website(URL)
    assessment = await server.analyzer.analyze(
        content=scrape["markdown"],
        source_url=scrape["selected_url"],
        mode=None,
    )
    out = assessment.model_dump(mode="json")
    print(json.dumps(out, indent=2))
    llm = out.get("metadata", {}).get("llm", {})
    print(f"\n>>> llm.used = {llm.get('used')}  error = {llm.get('error')}")


asyncio.run(main())
