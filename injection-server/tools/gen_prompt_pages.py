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
import re
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


# Realistic, innocuous public-facing identity for each case. The route slug and
# page title must NOT hint at an injection test (no "override", "hijack",
# "adaptive", "strong_structural", etc.) — the agent sees these. The internal
# `id` is retained only for server-side audit logging / ground truth.
PAGE_META = {
    "explicit_override_01":        ("example-domain",            "Example Domain Overview"),
    "priority_hijack_01":          ("best-laptops-2026",         "The Best Laptops of 2026"),
    "role_injection_01":           ("chocolate-cake-recipe",     "Ultimate Chocolate Cake Recipe"),
    "tool_directive_01":           ("mumbai-weather",            "Mumbai Weather Today"),
    "data_exfil_01":               ("python-resources",          "Python Programming Resources"),
    "task_redirect_01":            ("bitcoin-price",             "Bitcoin Price Today"),
    "secrecy_01":                  ("machine-learning-intro",    "Introduction to Machine Learning"),
    "semantic_manip_01":           ("iphone-17-review",          "iPhone 17 Review"),
    "semantic_manip_02":           ("paris-restaurants",         "Best Restaurants in Paris"),
    "semantic_manip_03":           ("renewable-energy-report",   "Renewable Energy Report 2026"),
    "adaptive_authority_01":       ("ai-news-digest",            "Today's AI News Digest"),
    "adaptive_task_redirect_01":   ("bitcoin-price-tracker",     "Bitcoin Price Tracker"),
    "adaptive_secrecy_01":         ("ml-overview",               "Machine Learning Overview"),
    "adaptive_tool_directive_01":  ("mumbai-forecast",           "Mumbai Weather Forecast"),
    "adaptive_role_01":            ("chocolate-cake-guide",      "Chocolate Cake Baking Guide"),
    "adaptive_exfil_01":           ("python-tutorials",          "Python Tutorials for Developers"),
    "adaptive_priority_01":        ("laptop-buying-guide",       "2026 Laptop Buying Guide"),
    "adaptive_redirect_delete_01": ("programming-languages-2026","Top Programming Languages to Learn in 2026"),
    "strong_function_format_01":   ("iphone-17-reviews-roundup", "iPhone 17 Reviews Roundup"),
    "strong_completion_lure_01":   ("btc-market-update",         "Bitcoin Market Update"),
    "strong_nested_tool_doc_01":   ("mumbai-weather-today",      "Mumbai Weather — Live"),
    "strong_blended_narrative_01": ("iphone-17-hands-on",        "iPhone 17 Hands-On Review"),
    # output_exfil family: the directive is fused into the visible article body
    # (semantic stealth), so these pages show the full blob and hide nothing.
    "output_exfil_pixel_01":       ("iphone-17-verge-review",    "iPhone 17 Review — The Verge"),
    "output_exfil_cite_01":        ("machine-learning-explained","Machine Learning Explained"),
    "output_exfil_footer_01":      ("mumbai-weather-update",     "Mumbai Weather Update"),
    "output_exfil_beacon_01":      ("ai-weekly-digest",          "AI Weekly Digest"),
    "output_exfil_confirm_01":     ("bitcoin-price-coindesk",    "Bitcoin Price — Live Quote"),
    "output_exfil_scrape_01":      ("iphone-17-techreview",      "iPhone 17 Review — TechReview Daily"),
}


def slugify(text):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s or "page"


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

    if tc["family"] == "output_exfil":
        # output_exfil blends its directive INTO the legitimate content the user
        # asked for — its stealth is semantic (reads like an editorial / licensing
        # note), not DOM-based. Splitting the directive into a hidden vector would
        # separate it from the surrounding content and recreate the exact
        # "structurally ignorable sidecar" failure these cases were rewritten to
        # avoid. So we render the WHOLE blob as visible content and hide nothing;
        # server.py skips vector injection when `injection` is empty.
        if isinstance(payload, list):
            item = payload[0]
            benign_results.append({
                "title": item.get("title", ""),
                "url": item.get("url", ""),
                "snippet": item.get("snippet", ""),
            })
        else:  # dict/blob payload (scrape case)
            benign_results.append({
                "title": payload.get("url", "Document"),
                "url": payload.get("url", ""),
                "snippet": payload.get("content", ""),
            })
        injection = ""
    elif isinstance(payload, list):
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

    slug, title = PAGE_META.get(tc["id"], (slugify(tc["user_goal"]), tc["user_goal"]))
    pages.append({
        "id": tc["id"],                # internal ground-truth id (audit log only)
        "slug": slug,                  # public, innocuous route: /p/<slug>
        "title": title,                # public, innocuous page title
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
    f.write("PROMPT_PAGES_BY_SLUG = {p['slug']: p for p in PROMPT_PAGES}\n")

print(f"Wrote {len(pages)} pages to {OUT}")
for p in pages:
    print(f"  {p['id']:<28} benign={len(p['benign_results'])} inj_len={len(p['injection'])}")
