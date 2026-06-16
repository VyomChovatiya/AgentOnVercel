from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from openai import OpenAI
from ddgs import DDGS
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import json, time, httpx, asyncio

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

lm = OpenAI(base_url="http://localhost:1234/v1", api_key="lm-studio")
executor = ThreadPoolExecutor(max_workers=2)
semaphore = asyncio.Semaphore(1)

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web and return top results with titles, URLs, and snippets.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "max_results": {"type": "integer", "default": 5}
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scrape_url",
            "description": "Scrape and extract clean text content from a URL.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "selector": {"type": "string"}
                },
                "required": ["url"]
            }
        }
    }
]

def web_search(query: str, max_results: int = 5):
    for attempt in range(3):
        try:
            with DDGS() as ddgs:
                results = list(ddgs.text(query, max_results=max_results, backend="api"))
            if results:
                return [{"title": r["title"], "url": r["href"], "snippet": r["body"]} for r in results]
            time.sleep(2)
        except Exception as e:
            print(f"[web_search error] attempt {attempt+1}: {e}")
            time.sleep(2)
    return {"error": "Search returned no results after 3 attempts"}

def _scrape_sync(url: str, selector: str = None):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url, wait_until="domcontentloaded", timeout=15000)
        html = page.content()
        browser.close()
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
        tag.decompose()
    if selector:
        target = soup.select_one(selector)
        text = target.get_text(separator="\n", strip=True) if target else "Selector not found"
    else:
        text = soup.get_text(separator="\n", strip=True)
    return {"url": url, "content": text[:8000]}

def scrape_url(url: str, selector: str = None):
    try:
        future = executor.submit(_scrape_sync, url, selector)
        return future.result(timeout=20)
    except Exception as e:
        print(f"[scrape_url error] {url}: {e}")
        return {"error": str(e)}

REGISTRY = {"web_search": web_search, "scrape_url": scrape_url}

def run_tools(messages, model, extra):
    """Run tool loop (non-streaming), return final messages + reasoning + content."""
    all_tools = TOOLS

    while True:
        response = lm.chat.completions.create(
            model=model,
            messages=messages,
            tools=all_tools,
            **{k: v for k, v in extra.items() if k != "stream"}
        )
        msg = response.choices[0].message
        finish_reason = response.choices[0].finish_reason

        if finish_reason != "tool_calls" or not msg.tool_calls:
            # Extract reasoning if present
            reasoning = getattr(msg, "reasoning_content", None)
            return messages, reasoning, msg.content or ""

        messages.append(msg.model_dump())
        for tc in msg.tool_calls:
            fn_name = tc.function.name
            try:
                args = json.loads(tc.function.arguments)
                result = REGISTRY[fn_name](**args) if fn_name in REGISTRY else {"error": f"Unknown tool: {fn_name}"}
            except Exception as e:
                result = {"error": str(e)}
            print(f"[tool] {fn_name} -> {str(result)[:200]}")
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result)})

async def stream_response(messages, model, extra, reasoning):
    """Stream the final response as SSE, prepending reasoning block if present."""

    # First emit reasoning block if we have it
    if reasoning:
        chunk = {
            "choices": [{
                "delta": {"reasoning_content": reasoning},
                "finish_reason": None,
                "index": 0
            }]
        }
        yield f"data: {json.dumps(chunk)}\n\n"

    # Now stream the actual content
    stream = lm.chat.completions.create(
        model=model,
        messages=messages,
        stream=True,
        **{k: v for k, v in extra.items() if k != "stream"}
    )

    for chunk in stream:
        yield f"data: {json.dumps(chunk.model_dump())}\n\n"

    yield "data: [DONE]\n\n"

@app.post("/v1/chat/completions")
async def proxy(request: Request):
    async with semaphore:
        body = await request.json()
        messages = body["messages"]
        model = body.get("model", "local-model")
        extra = {k: v for k, v in body.items() if k not in ("messages", "tools", "model")}
        wants_stream = body.get("stream", False)

        # Always run tool loop non-streaming first
        messages, reasoning, content = await asyncio.get_event_loop().run_in_executor(
            None, lambda: run_tools(list(messages), model, extra)
        )

        if wants_stream:
            # Append final assistant message and stream it
            messages.append({"role": "assistant", "content": content})
            return StreamingResponse(
                stream_response(messages, model, extra, reasoning),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
            )
        else:
            # Non-streaming: do one final call to get proper response object
            final = lm.chat.completions.create(
                model=model,
                messages=messages,
                **{k: v for k, v in extra.items() if k != "stream"}
            )
            result = final.model_dump()
            # Inject reasoning into response if present
            if reasoning:
                result["choices"][0]["message"]["reasoning_content"] = reasoning
            return JSONResponse(result)

@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def passthrough(path: str, request: Request):
    body = await request.body()
    async with httpx.AsyncClient() as client:
        resp = await client.request(
            method=request.method,
            url=f"http://localhost:1234/v1/{path}",
            content=body,
            headers={"Content-Type": "application/json"}
        )
    return JSONResponse(resp.json())