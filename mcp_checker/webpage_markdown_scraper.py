from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup
from ddgs import DDGS


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)


def find_and_scrape_website(website_or_url: str, max_results: int = 5) -> dict:
    query = website_or_url.strip()
    if not query:
        raise ValueError("website_or_url is required.")

    search_results = [] if _looks_like_url(query) else search_duckduckgo_results(query, max_results=max_results)
    candidate_urls = [query] if _looks_like_url(query) else [item["url"] for item in search_results]
    if not candidate_urls:
        raise ValueError(f"No search result found for: {website_or_url}")

    page = None
    errors = []
    for candidate_url in candidate_urls:
        url = candidate_url if candidate_url.startswith(("http://", "https://")) else f"https://{candidate_url}"
        try:
            page = scrape_url_as_markdown(url)
            break
        except Exception as exc:
            errors.append(f"{url}: {exc}")
            if _looks_like_url(query):
                break
    if page is None:
        raise ValueError(f"Could not scrape any candidate page. Errors: {'; '.join(errors)}")

    return {
        "query": website_or_url,
        "selected_url": page["url"],
        "title": page["title"],
        "markdown": page["markdown"],
        "search_results": search_results,
    }


def search_duckduckgo_results(query: str, max_results: int = 5) -> list[dict]:
    with DDGS() as ddgs:
        results = list(ddgs.text(query, max_results=max_results))
    return [
        {
            "title": item.get("title", ""),
            "url": item.get("href", ""),
            "snippet": item.get("body", ""),
        }
        for item in results
        if item.get("href")
    ]


def scrape_url_as_markdown(url: str) -> dict:
    with httpx.Client(
        follow_redirects=True,
        timeout=20,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
    ) as client:
        response = client.get(url)
        response.raise_for_status()

    final_url = str(response.url)
    title, markdown = convert_html_to_markdown(response.text)
    return {"url": final_url, "title": title, "markdown": markdown}


def convert_html_to_markdown(html: str) -> tuple[str, str]:
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""

    for tag in soup(["script", "style", "noscript", "svg", "template", "iframe"]):
        tag.decompose()

    root = soup.body or soup
    try:
        from markdownify import markdownify as markdownify_html

        markdown = markdownify_html(str(root), heading_style="ATX", bullets="-").strip()
    except Exception:
        markdown = _bs4_markdown(root).strip()

    return title, _compact_markdown(markdown)


def _looks_like_url(value: str) -> bool:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return bool(parsed.netloc and "." in parsed.netloc)


def _compact_markdown(markdown: str) -> str:
    markdown = re.sub(r"\n{3,}", "\n\n", markdown)
    return "\n".join(line.rstrip() for line in markdown.splitlines()).strip()


def _bs4_markdown(root) -> str:
    from bs4 import NavigableString

    def inline(el) -> str:
        out = []
        for child in el.children:
            if isinstance(child, NavigableString):
                out.append(str(child))
            elif child.name in {"strong", "b"}:
                out.append(f"**{inline(child).strip()}**")
            elif child.name in {"em", "i"}:
                out.append(f"*{inline(child).strip()}*")
            elif child.name == "code":
                out.append(f"`{child.get_text(strip=True)}`")
            elif child.name == "a":
                text = inline(child).strip() or child.get("href", "")
                href = child.get("href", "")
                out.append(f"[{text}]({href})" if href else text)
            elif child.name == "img":
                src = child.get("src", "")
                out.append(f"![{child.get('alt', '')}]({src})" if src else "")
            elif child.name == "br":
                out.append("\n")
            else:
                out.append(inline(child))
        return "".join(out)

    parts = []

    def walk(el) -> None:
        for child in el.children:
            if isinstance(child, NavigableString):
                text = str(child).strip()
                if text:
                    parts.append(text)
            elif child.name in {"h1", "h2", "h3", "h4", "h5", "h6"}:
                parts.append("#" * int(child.name[1]) + " " + inline(child).strip())
            elif child.name == "p":
                text = inline(child).strip()
                if text:
                    parts.append(text)
            elif child.name in {"ul", "ol"}:
                for index, item in enumerate(child.find_all("li", recursive=False)):
                    marker = "-" if child.name == "ul" else f"{index + 1}."
                    parts.append(f"{marker} {inline(item).strip()}")
            elif child.name == "blockquote":
                parts.append("> " + inline(child).strip())
            elif child.name == "pre":
                parts.append("```\n" + child.get_text() + "\n```")
            elif child.name == "hr":
                parts.append("---")
            elif child.name == "img":
                src = child.get("src", "")
                if src:
                    parts.append(f"![{child.get('alt', '')}]({src})")
            else:
                walk(child)

    walk(root)
    return "\n\n".join(part for part in parts if part.strip())
