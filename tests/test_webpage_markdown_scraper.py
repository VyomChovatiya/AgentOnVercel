from mcp_checker import webpage_markdown_scraper
from mcp_checker.webpage_markdown_scraper import convert_html_to_markdown, find_and_scrape_website


def test_convert_html_to_markdown_extracts_title_and_content():
    html = """
    <html>
      <head><title>Example Page</title><script>ignore me</script></head>
      <body>
        <h1>Hello</h1>
        <p>Read the <a href="https://example.com/docs">docs</a>.</p>
      </body>
    </html>
    """

    title, markdown = convert_html_to_markdown(html)

    assert title == "Example Page"
    assert "Hello" in markdown
    assert "docs" in markdown
    assert "ignore me" not in markdown


def test_find_and_scrape_website_accepts_direct_url(monkeypatch):
    calls = {}

    def fake_fetch(url):
        calls["url"] = url
        return {"url": "https://example.com/final", "title": "Example", "markdown": "content"}

    monkeypatch.setattr(webpage_markdown_scraper, "scrape_url_as_markdown", fake_fetch)

    result = find_and_scrape_website("example.com/page")

    assert calls["url"] == "https://example.com/page"
    assert result["selected_url"] == "https://example.com/final"
    assert result["search_results"] == []


def test_find_and_scrape_website_accepts_website_name(monkeypatch):
    monkeypatch.setattr(
        webpage_markdown_scraper,
        "search_duckduckgo_results",
        lambda query, max_results=5: [{"title": "Example", "url": "https://example.com", "snippet": ""}],
    )
    monkeypatch.setattr(
        webpage_markdown_scraper,
        "scrape_url_as_markdown",
        lambda url: {"url": url, "title": "Example", "markdown": "content"},
    )

    result = find_and_scrape_website("example website")

    assert result["selected_url"] == "https://example.com"
    assert result["search_results"][0]["title"] == "Example"


def test_find_and_scrape_website_tries_next_search_result(monkeypatch):
    monkeypatch.setattr(
        webpage_markdown_scraper,
        "search_duckduckgo_results",
        lambda query, max_results=5: [
            {"title": "Blocked", "url": "https://blocked.example", "snippet": ""},
            {"title": "Works", "url": "https://works.example", "snippet": ""},
        ],
    )

    def fake_fetch(url):
        if "blocked" in url:
            raise RuntimeError("blocked")
        return {"url": url, "title": "Works", "markdown": "content"}

    monkeypatch.setattr(webpage_markdown_scraper, "scrape_url_as_markdown", fake_fetch)

    result = find_and_scrape_website("example website")

    assert result["selected_url"] == "https://works.example"
