from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from openai import OpenAI
from ddgs import DDGS
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import json, time, httpx, asyncio, io, pypdf, docx, os, smtplib, imaplib, email
from email.header import decode_header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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
    },
    {
        "type": "function",
        "function": {
            "name": "exa_search",
            "description": "Perform a neural search using Exa API and get high-quality web pages with highlights.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The search query optimized for LLMs"},
                    "num_results": {"type": "integer", "default": 5, "description": "Number of results to return"}
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "jina_reader",
            "description": "Fetch clean, markdown-formatted reader content of a specific URL using Jina AI Reader.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL of the webpage to read"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send/write a new email to a recipient using SMTP.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to_email": {"type": "string", "description": "Recipient's email address"},
                    "subject": {"type": "string", "description": "Subject line of the email"},
                    "body": {"type": "string", "description": "Email body content"}
                },
                "required": ["to_email", "subject", "body"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_emails",
            "description": "Fetch, read, and list the latest emails from a specified IMAP folder.",
            "parameters": {
                "type": "object",
                "properties": {
                    "folder": {"type": "string", "default": "INBOX", "description": "IMAP folder to retrieve emails from"},
                    "limit": {"type": "integer", "default": 5, "description": "Maximum number of emails to retrieve"}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "update_email_status",
            "description": "Modify email status (mark as read/unread or delete) using IMAP.",
            "parameters": {
                "type": "object",
                "properties": {
                    "email_id": {"type": "string", "description": "Unique IMAP ID of the email"},
                    "action": {"type": "string", "enum": ["mark_read", "mark_unread", "delete"], "description": "The modification action to apply"},
                    "folder": {"type": "string", "default": "INBOX", "description": "IMAP folder containing the email"}
                },
                "required": ["email_id", "action"]
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

def exa_search(query: str, num_results: int = 5):
    api_key = os.environ.get("EXA_API_KEY")
    if not api_key:
        return {"error": "EXA_API_KEY environment variable is not configured."}
    try:
        headers = {
            "x-api-key": api_key,
            "Content-Type": "application/json"
        }
        payload = {
            "query": query,
            "numResults": num_results,
            "useAutoprompt": True
        }
        resp = httpx.post("https://api.exa.ai/search", json=payload, headers=headers, timeout=15)
        if resp.status_code != 200:
            return {"error": f"Exa API error: {resp.text}"}
        data = resp.json()
        results = []
        for r in data.get("results", []):
            results.append({
                "title": r.get("title"),
                "url": r.get("url"),
                "score": r.get("score"),
                "snippet": r.get("text", "")[:300]
            })
        return {"results": results}
    except Exception as e:
        return {"error": str(e)}

def jina_reader(url: str):
    try:
        headers = {}
        api_key = os.environ.get("JINA_API_KEY")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        jina_url = f"https://r.jina.ai/{url}"
        resp = httpx.get(jina_url, headers=headers, timeout=20)
        if resp.status_code != 200:
            return {"error": f"Jina Reader error: {resp.text}"}
        return {"url": url, "content": resp.text[:10000]}
    except Exception as e:
        return {"error": str(e)}

def send_email(to_email: str, subject: str, body: str):
    sender_email = os.environ.get("SMTP_SENDER_EMAIL")
    sender_password = os.environ.get("SMTP_SENDER_PASSWORD")
    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    if not sender_email or not sender_password:
        return {"error": "SMTP credentials not configured. Please set SMTP_SENDER_EMAIL and SMTP_SENDER_PASSWORD."}
    try:
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, msg.as_string())
        server.quit()
        return {"status": "success", "message": f"Email sent successfully to {to_email}"}
    except Exception as e:
        return {"error": str(e)}

def get_emails(folder: str = "INBOX", limit: int = 5):
    sender_email = os.environ.get("SMTP_SENDER_EMAIL")
    sender_password = os.environ.get("SMTP_SENDER_PASSWORD")
    imap_server = os.environ.get("IMAP_SERVER", "imap.gmail.com")
    if not sender_email or not sender_password:
        return {"error": "IMAP credentials not configured. Please set SMTP_SENDER_EMAIL and SMTP_SENDER_PASSWORD."}
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(sender_email, sender_password)
        mail.select(folder)
        status, messages = mail.search(None, "ALL")
        if status != "OK":
            mail.logout()
            return {"error": "Failed to search folder"}
        email_ids = messages[0].split()
        latest_email_ids = email_ids[-limit:]
        results = []
        for e_id in reversed(latest_email_ids):
            res_id = e_id.decode()
            status, msg_data = mail.fetch(e_id, "(RFC822)")
            if status != "OK":
                continue
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject, encoding = decode_header(msg["Subject"] or "")[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding or "utf-8", errors="ignore")
                    from_, encoding = decode_header(msg["From"] or "")[0]
                    if isinstance(from_, bytes):
                        from_ = from_.decode(encoding or "utf-8", errors="ignore")
                    date = msg["Date"]
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            content_disposition = str(part.get("Content-Disposition"))
                            if content_type == "text/plain" and "attachment" not in content_disposition:
                                body_payload = part.get_payload(decode=True)
                                if body_payload:
                                    body = body_payload.decode(errors="ignore")
                                    break
                    else:
                        body_payload = msg.get_payload(decode=True)
                        if body_payload:
                            body = body_payload.decode(errors="ignore")
                    results.append({
                        "id": res_id,
                        "from": from_,
                        "subject": subject,
                        "date": date,
                        "snippet": body[:300].strip()
                    })
        mail.logout()
        return {"emails": results}
    except Exception as e:
        return {"error": str(e)}

def update_email_status(email_id: str, action: str, folder: str = "INBOX"):
    sender_email = os.environ.get("SMTP_SENDER_EMAIL")
    sender_password = os.environ.get("SMTP_SENDER_PASSWORD")
    imap_server = os.environ.get("IMAP_SERVER", "imap.gmail.com")
    if not sender_email or not sender_password:
        return {"error": "IMAP credentials not configured. Please set SMTP_SENDER_EMAIL and SMTP_SENDER_PASSWORD."}
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(sender_email, sender_password)
        mail.select(folder)
        if action == "mark_read":
            mail.store(email_id, "+FLAGS", "\\Seen")
            msg = f"Email {email_id} marked as read"
        elif action == "mark_unread":
            mail.store(email_id, "-FLAGS", "\\Seen")
            msg = f"Email {email_id} marked as unread"
        elif action == "delete":
            mail.store(email_id, "+FLAGS", "\\Deleted")
            mail.expunge()
            msg = f"Email {email_id} deleted"
        else:
            mail.logout()
            return {"error": f"Unknown action: {action}"}
        mail.logout()
        return {"status": "success", "message": msg}
    except Exception as e:
        return {"error": str(e)}

REGISTRY = {
    "web_search": web_search,
    "scrape_url": scrape_url,
    "exa_search": exa_search,
    "jina_reader": jina_reader,
    "send_email": send_email,
    "get_emails": get_emails,
    "update_email_status": update_email_status
}

def run_tools(messages, model, extra):
    """Run tool loop (non-streaming), return final messages + response object."""
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
            return messages, response

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

async def stream_response(reasoning, content):
    """Stream pre-generated reasoning and content as SSE chunks."""
    # First emit reasoning block if we have it
    if reasoning:
        chunk_size = 40
        for i in range(0, len(reasoning), chunk_size):
            chunk = {
                "choices": [{
                    "delta": {"reasoning_content": reasoning[i:i+chunk_size]},
                    "finish_reason": None,
                    "index": 0
                }]
            }
            yield f"data: {json.dumps(chunk)}\n\n"
            await asyncio.sleep(0.005)

    # Now stream the actual content
    if content:
        chunk_size = 20
        for i in range(0, len(content), chunk_size):
            chunk = {
                "choices": [{
                    "delta": {"content": content[i:i+chunk_size]},
                    "finish_reason": None,
                    "index": 0
                }]
            }
            yield f"data: {json.dumps(chunk)}\n\n"
            await asyncio.sleep(0.005)

    yield "data: [DONE]\n\n"

@app.post("/v1/chat/completions")
async def proxy(request: Request):
    async with semaphore:
        body = await request.json()
        messages = body["messages"]
        model = body.get("model", "local-model")
        extra = {k: v for k, v in body.items() if k not in ("messages", "tools", "model")}
        wants_stream = body.get("stream", False)

        # Always run tool loop non-streaming first to resolve all tool calling
        messages, response = await asyncio.get_event_loop().run_in_executor(
            None, lambda: run_tools(list(messages), model, extra)
        )

        reasoning = getattr(response.choices[0].message, "reasoning_content", None)
        content = response.choices[0].message.content or ""

        if wants_stream:
            return StreamingResponse(
                stream_response(reasoning, content),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
            )
        else:
            result = response.model_dump()
            # Inject reasoning into response if present
            if reasoning:
                result["choices"][0]["message"]["reasoning_content"] = reasoning
            return JSONResponse(result)

@app.post("/v1/parse-document")
async def parse_document(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        filename = file.filename.lower()
        if filename.endswith(".pdf"):
            reader = pypdf.PdfReader(io.BytesIO(contents))
            text = ""
            for page in reader.pages:
                t = page.extract_text()
                if t:
                    text += t + "\n"
            return {"content": text}
        elif filename.endswith(".docx"):
            doc = docx.Document(io.BytesIO(contents))
            text = ""
            for para in doc.paragraphs:
                if para.text:
                    text += para.text + "\n"
            for table in doc.tables:
                for row in table.rows:
                    for cell in row.cells:
                        text += cell.text + "\n"
            return {"content": text}
        else:
            return {"content": contents.decode("utf-8", errors="ignore")}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

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