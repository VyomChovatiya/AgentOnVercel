# Injection Server

A mock "vulnerable" enterprise website used to test an AI agent against indirect
prompt injection (IPI). It serves realistic-looking pages and hides malicious
instructions inside the page DOM using a range of stealth vectors, so you can
point your agent at a real URL and observe whether it obeys hidden instructions
it scrapes from the page.

This folder is a vendored copy of the `server` branch of
`blueinfy-solutions/aiagent-trap-detection`, plus a set of prompt pages generated
from the repo's own `evaluate_defense.py`.

## Files

| File | Purpose |
|------|---------|
| `server.py` | The HTTP server and all page/route logic. |
| `vectors.py` | Stealth injection vectors — *where/how* a payload is hidden in HTML (hidden div, meta tag, aria-label, base64, JSON-LD, comment, …). |
| `config.py` | Original mock-catalog scenario + its hijack payloads. |
| `prompt_pages.py` | Auto-generated. 22 attack cases imported from `../evaluate_defense.py`, one per page. |
| `tools/gen_prompt_pages.py` | Regenerates `prompt_pages.py` from `../evaluate_defense.py`. |

## Run it

```bash
cd injection-server
python server.py
```

Each attack case is served at an innocuous, topic-based slug (the URL must not
hint that it's an injection test, since the agent sees it). e.g.:

```
http://localhost:8080/p/iphone-17-review
http://localhost:8080/p/best-laptops-2026
http://localhost:8080/p/bitcoin-price
```

The internal case id (e.g. `semantic_manip_01`) is kept only for the server-side
audit log. The full **slug → attack-goal** mapping is printed to the console when
the server starts (operator ground truth) — it is intentionally NOT shown on the
site. A plain "Knowledge Base" listing of the page links lives at:

```
http://localhost:8080/prompts
```

Each page shows only benign content; the malicious instruction is hidden in the
DOM via a stealth vector (default: `hidden_div`). Override the vector per request:

```
http://localhost:8080/p/iphone-17-review?vector=meta_tag
http://localhost:8080/p/iphone-17-review?vector=json_ld
```

Available vector ids are the keys of `VECTOR_MAP` in `vectors.py`.

> Note: `hidden_div` holds arbitrary text safely. Attribute-based vectors
> (`meta_tag`, `aria_label`, `link_title`, …) place the payload inside an HTML
> attribute, so a payload containing a double quote (e.g. `strong_nested_tool_doc_01`)
> may break the markup with those vectors. `hidden_div` is the safe default.

The original mock-catalog routes still work too:

```
http://localhost:8080/catalog
http://localhost:8080/catalog?vector=hidden_div&payload=<urlencoded text>
```

Every request is logged server-side (ground truth) to `outputs/server_audit_*.log`,
including the page id, the vector used, and the attack goal.

## Deploying to a public URL (Render / Railway)

The server is pure Python stdlib at runtime and binds to `$PORT` / `0.0.0.0`, so
it runs unchanged on most cloud hosts. The repo must be pushed to GitHub first
(both platforms deploy from a connected repo + branch).

### Render — Blueprint (one click)
A `render.yaml` at the repo root already describes the service (`rootDir:
injection-server`). In the Render dashboard: **New → Blueprint**, connect this
repo and the `icon-defense` branch. Render builds and gives you a URL like
`https://injection-server.onrender.com`. Pages are then at
`https://injection-server.onrender.com/p/iphone-17-review`.

### Render — manual (no blueprint)
**New → Web Service**, connect the repo, then set:
- Root Directory: `injection-server`
- Build Command: `pip install -r requirements.txt`
- Start Command: `python server.py`

### Railway
**New Project → Deploy from GitHub repo**, then in service Settings:
- Root Directory: `injection-server`  (Railway reads the `Procfile` there)
- Railway injects `$PORT` automatically; no other config needed.

> Note: the **slug → attack-goal mapping is printed to the server logs at
> startup** (operator ground truth). On Render/Railway, read it from the service's
> log tab. The website itself never displays it.

> This server intentionally hosts content crafted to manipulate AI agents. It
> targets *your own* test agent and serves benign-looking pages to humans, but
> since the URL is public, prefer the free tier (which idles when unused) and
> take it down when you're done testing rather than leaving it up indefinitely.

## Regenerating the prompt pages

If you change the attack cases in `../evaluate_defense.py`, regenerate:

```bash
python injection-server/tools/gen_prompt_pages.py
```

This reads `evaluate_defense.py` from the repo root and rewrites `prompt_pages.py`.
It needs `evaluate_defense.py`'s dependencies importable (`pip install requests`).
