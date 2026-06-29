"""
gen_prompt_pages.py
────────────────────────────────────────────────────────────────────────────────
Regenerates injection-server/prompt_pages.py from the attack cases defined in
the repo-root evaluate_defense.py (TEST_CASES).

For each attack case it separates:
  - benign_results : the legitimate content shown as the VISIBLE page
  - injection      : the malicious instruction, which server.py hides in the DOM
                     via a stealth vector (see vectors.py / route /p/<id>)

Paths are resolved relative to THIS file, so it works from a fresh clone of the
repo no matter where the repo lives on disk. Run it from anywhere:

    python injection-server/tools/gen_prompt_pages.py

Requires the same deps as evaluate_defense.py (importing it pulls in `requests`).
"""
import json
import sys
import pprint
from pathlib import Path

# tools/ -> injection-server/ -> <repo root>
THIS = Path(__file__).resolve()
INJECTION_SERVER_DIR = THIS.parents[1]
REPO_ROOT = THIS.parents[2]

OUT = INJECTION_SERVER_DIR / "prompt_pages.py"

# Import TEST_CASES from the repo-root evaluate_defense.py
sys.path.insert(0, str(REPO_ROOT))
try:
    import evaluate_defense as e
except ImportError as exc:
    print(f"Could not import evaluate_defense.py from {REPO_ROOT}: {exc}")
    print("Make sure you are running this from within the repo and its deps are installed "
          "(pip install requests).")
    sys.exit(1)


def split_blob(title, url, blob):
    """Single text blob mixing benign + malicious -> (benign_result, injection)."""
    if "\n\n" in blob:
        prefix, rest = blob.split("\n\n", 1)
        return ({"title": title, "url": url, "snippet": prefix.strip()}, rest.strip())
    # No clean separator (the deliberately-blended narrative case): hide the
    # whole blob, show only a short benign placeholder.
    return ({"title": title, "url": url, "snippet": "(Article content continues below.)"}, blob.strip())


pages = []
for tc in e.TEST_CASES:
    if tc["benign"]:
        continue
    payload = json.loads(tc["payload"])

    benign_results = []   # visible page content
    injection = ""        # malicious instruction, hidden via vector

    if isinstance(payload, list):
        if len(payload) >= 2:
            # In every test case the malicious entry is the LAST list item,
            # preceded by genuine benign result(s). Positional split is more
            # reliable than indicator matching (some indicators are outcome
            # phrases that never appear in the payload itself).
            *benign_items, mal_item = payload
            for item in benign_items:
                benign_results.append({
                    "title": item.get("title", ""),
                    "url": item.get("url", ""),
                    "snippet": item.get("snippet", ""),
                })
            injection = mal_item.get("snippet", "")
            if "response_metadata" in mal_item:
                injection = injection + "\n" + json.dumps(mal_item["response_metadata"])
        else:
            # Single item blends benign + malicious in one snippet.
            item = payload[0]
            br, injection = split_blob(item.get("title", ""), item.get("url", ""), item.get("snippet", ""))
            benign_results.append(br)
    else:  # dict/blob payload: one content string mixing benign + malicious
        content = payload.get("content", "")
        br, injection = split_blob(payload.get("url", "Document"), payload.get("url", ""), content)
        benign_results.append(br)

    pages.append({
        "id": tc["id"],
        "family": tc["family"],
        "user_goal": tc["user_goal"],
        "attack_goal": tc["attack_goal"],
        "page_query": (tc.get("tool_args") or {}).get("query", ""),
        "benign_results": benign_results,
        "injection": injection,
        "success_indicators": tc["success_indicators"],
    })

header = '''# prompt_pages.py
"""
Auto-generated from the repo-root evaluate_defense.py TEST_CASES (attack cases only).

Each entry becomes its own page on the InjectionServer. The `benign_results`
are rendered as visible page content; the `injection` string is the malicious
instruction, hidden in the DOM via one of the stealth vectors in vectors.py
(see server.py route /p/<id>).

Regenerate with: python injection-server/tools/gen_prompt_pages.py
"""

PROMPT_PAGES = '''

with open(OUT, "w", encoding="utf-8") as f:
    f.write(header)
    f.write(pprint.pformat(pages, width=100, sort_dicts=False))
    f.write("\n\nPROMPT_PAGES_BY_ID = {p['id']: p for p in PROMPT_PAGES}\n")

print(f"Wrote {len(pages)} pages to {OUT}")
for p in pages:
    print(f"  {p['id']:<28} benign={len(p['benign_results'])} inj_len={len(p['injection'])}")
