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

Then open the index of generated prompt pages:

```
http://localhost:8080/prompts
```

Each attack case is its own page, e.g.:

```
http://localhost:8080/p/semantic_manip_01
http://localhost:8080/p/strong_blended_narrative_01
```

The page shows only benign content; the malicious instruction is hidden in the
DOM via a stealth vector (default: `hidden_div`). Override the vector per request:

```
http://localhost:8080/p/semantic_manip_01?vector=meta_tag
http://localhost:8080/p/semantic_manip_01?vector=json_ld
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

## Regenerating the prompt pages

If you change the attack cases in `../evaluate_defense.py`, regenerate:

```bash
python injection-server/tools/gen_prompt_pages.py
```

This reads `evaluate_defense.py` from the repo root and rewrites `prompt_pages.py`.
It needs `evaluate_defense.py`'s dependencies importable (`pip install requests`).
