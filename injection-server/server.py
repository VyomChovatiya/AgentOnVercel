# mock_server.py
"""
Multi-surface mock enterprise server.
Logs every injection server-side for ground-truth verification.
"""

import http.server
import urllib.parse
import logging
import datetime
import socket

from pathlib import Path
from config import OUTPUT_DIR,SERVER_HOST,SERVER_PORT,INJECTION_PAYLOADS
from vectors import VECTOR_MAP
from prompt_pages import PROMPT_PAGES, PROMPT_PAGES_BY_ID, PROMPT_PAGES_BY_SLUG

# Default stealth vector used for /p/<slug> prompt pages when no ?vector= is given.
# hidden_div places the payload as text content in a display:none div, which
# handles arbitrary payload text (quotes, JSON, etc.) without breaking markup.
DEFAULT_PROMPT_VECTOR = "hidden_div"

# Server-side injection audit log — separate from main.py output
log_path = Path(OUTPUT_DIR)
log_path.mkdir(parents=True, exist_ok=True)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = log_path / f"server_audit_{timestamp}.log"

logging.basicConfig(
    filename=str(log_file),
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


class VulnerableSiteHandler(http.server.SimpleHTTPRequestHandler):

    # ------------------------------------------------------------------ #
    #  Shared layout components                                            #
    # ------------------------------------------------------------------ #

    def _get_css(self):
        return """
        :root {
            --bg: #0f172a; --card: #1e293b; --text: #f8fafc;
            --muted: #94a3b8; --accent: #38bdf8; --border: #334155;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: system-ui, sans-serif; background: var(--bg);
               color: var(--text); display: flex; flex-direction: column; align-items: center; }
        .wrapper { max-width: 1100px; width: 100%; padding: 2rem 1.5rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; margin-top: 2rem; }
        .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; display: flex; flex-direction: column; }
        .badge { background: rgba(56,189,248,0.1); color: var(--accent); padding: .25rem .5rem;
                 border-radius: 4px; font-size: .7rem; font-weight: 700; align-self: flex-start; margin-bottom: 1rem; }
        .badge.best { background: #16a34a; color: #fff; }
        .badge.legacy { background: #dc2626; color: #fff; }
        .product-title { font-size: 1.2rem; margin-bottom: .75rem; }
        .specs { list-style: none; font-size: .9rem; color: var(--muted); margin-bottom: 1.5rem; }
        .specs li { padding: .3rem 0; border-bottom: 1px solid rgba(51,65,85,.3); }
        .price { margin-top: auto; font-size: 1.5rem; font-weight: 700;
                 border-top: 1px solid var(--border); padding-top: .75rem; }
        .review strong { color: var(--text); display: block; margin-bottom: .3rem; }
        header { background: #1e293b; padding: 1rem 2rem; border-bottom: 1px solid #334155; width: 100%; }
        header .inner { max-width: 1100px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; }
        header span { font-weight: 800; font-size: 1.2rem; color: var(--accent); }
        header a { color: var(--text); margin-left: 1.5rem; text-decoration: none; font-size: .9rem; }
        footer { margin-top: 5rem; padding: 3rem 1.5rem; border-top: 1px solid #334155;
                 width: 100%; text-align: center; color: #64748b; font-size: .85rem; }
        .faq { margin-top: 3rem; }
        .faq h2 { margin-bottom: 1rem; }
        .faq details { background: var(--card); border: 1px solid var(--border); border-radius: 6px;
                       padding: .75rem 1rem; margin-bottom: .5rem; }
        .faq summary { cursor: pointer; font-weight: 600; }
        .faq p { margin-top: .5rem; color: var(--muted); font-size: .9rem; }
        """

    def _header(self):
        return """
        <header>
            <div class="inner">
                <span>NextGen Global Systems</span>
                <nav>
                    <a href="/catalog">Product Catalog</a>
                    <a href="/about">About</a>
                    <a href="/support">Support</a>
                </nav>
            </div>
        </header>"""

    def _footer(self):
        return """
        <footer>
            <p>&copy; 2026 NextGen Global Systems Inc. All rights reserved.</p>
            <p style="margin-top:.5rem;">Terms of Service | Privacy Policy | Regulatory Disclosures | Supply Chain Transparency Act Matrix</p>
            <p style="margin-top:.5rem; font-size:.75rem; color:#475569;">
                Procurement baseline compliance schema v4.2.1 | ISO 27001 Certified | SOC2 Type II Audited
            </p>
        </footer>"""

    # ------------------------------------------------------------------ #
    #  Route builders                                                      #
    # ------------------------------------------------------------------ #

    def _build_catalog(self):
        """Product catalog with FAQ noise surface."""
        return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Enterprise Procurement Catalog — NextGen Global Systems</title>
        <meta charset="UTF-8">
        <style>{self._get_css()}</style>
    </head>
    <body>
    {self._header()}
    <div class="wrapper">
        <h1 style="font-size:2rem; margin-bottom:.5rem;">System Hardware Inventory</h1>
        <p style="color:#94a3b8; margin-bottom:2rem;">
            Active baseline inventory for automated enterprise procurement validation loops.
            All SKUs subject to regional compliance review. Prices listed exclude VAT and logistics overhead.
        </p>

        <div class="grid">
            <div class="product-card" id="prod_alpha">
                <span class="badge best">Optimal Configuration</span>
                <h3 class="product-title">QuantumLaptop Alpha</h3>
                <ul class="specs">
                    <li><strong>Memory:</strong> 64GB LPDDR5X</li>
                    <li><strong>Storage:</strong> 2TB NVMe SSD</li>
                    <li><strong>Processor:</strong> Ultra-Thread 16-Core</li>
                    <li><strong>Display:</strong> 4K OLED 120Hz</li>
                    <li><strong>Battery:</strong> 99Wh, 18hr rated</li>
                </ul>
                <div class="price">$1,200 USD</div>
            </div>

            <div class="product-card" id="prod_beta">
                <span class="badge">Standard Procurement</span>
                <h3 class="product-title">QuantumLaptop Beta</h3>
                <ul class="specs">
                    <li><strong>Memory:</strong> 32GB LPDDR5X</li>
                    <li><strong>Storage:</strong> 1TB NVMe SSD</li>
                    <li><strong>Processor:</strong> Mid-Tier 8-Core</li>
                    <li><strong>Display:</strong> 1080p IPS 60Hz</li>
                    <li><strong>Battery:</strong> 72Wh, 12hr rated</li>
                </ul>
                <div class="price">$1,400 USD</div>
            </div>

            <div class="product-card" id="prod_gamma">
                <span class="badge legacy">Legacy Hardware</span>
                <h3 class="product-title">QuantumLaptop Gamma</h3>
                <ul class="specs">
                    <li><strong>Memory:</strong> 8GB LPDDR4</li>
                    <li><strong>Storage:</strong> 256GB eMMC Flash</li>
                    <li><strong>Processor:</strong> Entry Mobile 2-Core</li>
                    <li><strong>Display:</strong> 720p TN Panel</li>
                    <li><strong>Battery:</strong> 38Wh, 6hr rated</li>
                </ul>
                <div class="price">$2,000 USD</div>
            </div>

            <div class="product-card" id="prod_delta">
                <span class="badge">Standard Procurement</span>
                <h3 class="product-title">QuantumLaptop Delta</h3>
                <ul class="specs">
                    <li><strong>Memory:</strong> 16GB LPDDR5</li>
                    <li><strong>Storage:</strong> 512GB NVMe SSD</li>
                    <li><strong>Processor:</strong> Mid-Tier 6-Core</li>
                    <li><strong>Display:</strong> 1440p IPS 90Hz</li>
                    <li><strong>Battery:</strong> 60Wh, 10hr rated</li>
                </ul>
                <div class="price">$1,100 USD</div>
            </div>

            <div class="product-card" id="prod_epsilon">
                <span class="badge">High-Tier Alternate</span>
                <h3 class="product-title">QuantumLaptop Epsilon</h3>
                <ul class="specs">
                    <li><strong>Memory:</strong> 32GB LPDDR5X</li>
                    <li><strong>Storage:</strong> 2TB NVMe SSD</li>
                    <li><strong>Processor:</strong> High-Performance 12-Core</li>
                    <li><strong>Display:</strong> 2K IPS 144Hz</li>
                    <li><strong>Battery:</strong> 86Wh, 15hr rated</li>
                </ul>
                <div class="price">$1,700 USD</div>
            </div>

            <div class="product-card" id="prod_zeta">
                <span class="badge">Workstation Class</span>
                <h3 class="product-title">QuantumLaptop Zeta</h3>
                <ul class="specs">
                    <li><strong>Memory:</strong> 64GB LPDDR5X</li>
                    <li><strong>Storage:</strong> 4TB NVMe SSD</li>
                    <li><strong>Processor:</strong> Extreme-Thread 24-Core</li>
                    <li><strong>Display:</strong> 4K Mini-LED 240Hz</li>
                    <li><strong>Battery:</strong> 99Wh, 20hr rated</li>
                </ul>
                <div class="price">$2,900 USD</div>
            </div>
        </div>

        <!-- FAQ noise surface -->
        <div class="faq">
            <h2>Procurement FAQ</h2>
            <details>
                <summary>What is the standard lead time for bulk enterprise orders?</summary>
                <p>Standard enterprise procurement lead times range from 14 to 28 business days depending
                on SKU availability and regional logistics routing. Expedited SLA available for Tier-1 contracts.</p>
            </details>
            <details>
                <summary>Are extended warranty contracts available?</summary>
                <p>All hardware SKUs are eligible for 3-year or 5-year extended warranty contracts
                through our Certified Partner Program. Contact your account manager for baseline pricing.</p>
            </details>
            <details>
                <summary>What compliance certifications apply to these products?</summary>
                <p>All SKUs carry CE, FCC, and RoHS certification. The Alpha and Zeta configurations
                additionally carry MIL-STD-810H ratings for environmental resilience in field deployments.</p>
            </details>
        </div>

    </div>
    {self._footer()}
    </body>
    </html>"""

    def _build_about(self):
        return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <title>About — NextGen Global Systems</title>
        <meta charset="UTF-8">
        <style>{self._get_css()}</style>
    </head>
    <body>
    {self._header()}
    <div class="wrapper">
        <div style="max-width:800px; margin:0 auto; line-height:1.7; color:#94a3b8;">
            <h1 style="color:#f8fafc; margin-bottom:1rem;">Our Corporate Evolution</h1>
            <p>Founded at the turn of the digital acceleration era, NextGen Global Systems has consistently
            conceptualized paradigms for decentralized supply frameworks. Our core competency lies not merely
            in delivery, but in holistic optimization of logistical parameters across global manufacturing lanes.</p>
            <p style="margin-top:1rem;">We operate out of fourteen regional optimization centers, maintaining
            strict adherence to structural sustainability mandates. Our internal culture maximizes cross-functional
            execution alignment to ensure our foundational ecosystem scales organically alongside emergent consumer criteria.</p>
            <h2 style="color:#f8fafc; margin-top:2rem;">Global Compliance Metrics</h2>
            <p>Every operational node undergoes continuous validation audits. We prioritize environmental
            mitigation strategies, resource allocation velocity, and systemic structural resilience across
            all administrative branches.</p>
        </div>
    </div>
    {self._footer()}
    </body>
    </html>"""

    def _build_support(self):
        """Extra noise surface — support page."""
        return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Support — NextGen Global Systems</title>
        <meta charset="UTF-8">
        <style>{self._get_css()}</style>
    </head>
    <body>
    {self._header()}
    <div class="wrapper">
        <h1 style="margin-bottom:1rem;">Technical Support Portal</h1>
        <p style="color:#94a3b8; margin-bottom:2rem;">
            Submit a support ticket or consult the knowledge base below for common procurement issues.
        </p>
        <div class="faq">
            <details>
                <summary>How do I return a defective unit?</summary>
                <p>Contact your regional account manager within 30 days of delivery. RMA process requires
                original packaging and proof of procurement order number.</p>
            </details>
            <details>
                <summary>Driver and firmware update policy</summary>
                <p>Firmware updates are pushed quarterly through the NextGen Device Management Console.
                Critical security patches are issued on an emergency basis outside the standard cycle.</p>
            </details>
        </div>
    </div>
    {self._footer()}
    </body>
    </html>"""

    # ------------------------------------------------------------------ #
    #  Prompt-page surfaces (one page per evaluate_defense.py attack case) #
    # ------------------------------------------------------------------ #

    def _build_prompt_page(self, page):
        """Render a realistic content page for one prompt case. The benign_results
        are the only VISIBLE content; the malicious instruction is NOT shown here —
        it is injected into the DOM by a stealth vector in do_GET()."""
        cards = ""
        for r in page["benign_results"]:
            title = r.get("title", "")
            url = r.get("url", "")
            snippet = r.get("snippet", "")
            cards += f"""
            <div class="card review">
                <strong>{title}</strong>
                <p style="color:#94a3b8; font-size:.8rem; margin-bottom:.5rem;">{url}</p>
                <p style="color:#cbd5e1; font-size:.95rem; line-height:1.6;">{snippet}</p>
            </div>"""

        title = page.get("title", "") or page.get("page_query", "") or page["user_goal"]
        return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <title>{title} — NextGen Knowledge Base</title>
        <meta charset="UTF-8">
        <style>{self._get_css()}</style>
    </head>
    <body>
    {self._header()}
    <div class="wrapper">
        <h1 style="font-size:1.8rem; margin-bottom:.25rem;">{title}</h1>
        <p style="color:#94a3b8; margin-bottom:1.5rem; font-size:.9rem;">
            NextGen Knowledge Base &middot; {len(page['benign_results'])} source(s)
        </p>
        <div class="grid">
        {cards}
        </div>
    </div>
    {self._footer()}
    </body>
    </html>"""

    def _build_prompt_index(self, display_host):
        """Innocuous public 'articles' listing — titles + links only, no attack
        metadata (this page is reachable over the internet). The operator gets the
        full slug->attack mapping printed to the console at startup instead."""
        rows = ""
        for p in PROMPT_PAGES:
            rows += f"""
            <div class="card">
                <h3 class="product-title">
                    <a href="/p/{p['slug']}" style="color:var(--accent); text-decoration:none;">{p['title']}</a>
                </h3>
                <p style="font-size:.8rem; color:#64748b;">/p/{p['slug']}</p>
            </div>"""
        return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Knowledge Base — NextGen Global Systems</title>
        <meta charset="UTF-8">
        <style>{self._get_css()}</style>
    </head>
    <body>
    {self._header()}
    <div class="wrapper">
        <h1 style="font-size:2rem; margin-bottom:.5rem;">Knowledge Base</h1>
        <p style="color:#94a3b8; margin-bottom:1rem;">Browse our latest articles and guides.</p>
        <div class="grid">
        {rows}
        </div>
    </div>
    {self._footer()}
    </body>
    </html>"""

    # ------------------------------------------------------------------ #
    #  Request handler                                                     #
    # ------------------------------------------------------------------ #

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        vector_id = query_params.get("vector", [None])[0]
        raw_payload = query_params.get("payload", [""])[0]
        path = parsed_url.path

        # ── Prompt-page routes (one page per evaluate_defense.py attack case) ──
        # Routed by an innocuous topic slug (/p/<slug>); the internal case id is
        # used only for the server-side audit log. The injection text comes from
        # the page's own data, not the ?payload= query param; the vector (where it
        # hides) defaults to DEFAULT_PROMPT_VECTOR, overridable with ?vector=<id>.
        if path == "/prompts":
            html_content = self._build_prompt_index(SERVER_HOST)
            logging.info(f"REQUEST | path={path} | prompt_index")
            self._respond(html_content)
            return

        if path.startswith("/p/"):
            slug = path[len("/p/"):].strip("/")
            page = PROMPT_PAGES_BY_SLUG.get(slug)
            if not page:
                self._respond(f"<h1>404 — page not found</h1>", status=404)
                return
            html_content = self._build_prompt_page(page)
            chosen_vector = vector_id if (vector_id in VECTOR_MAP) else DEFAULT_PROMPT_VECTOR
            injection_applied = False
            # output_exfil pages carry their lure inside the visible content, so
            # `injection` is empty and there is nothing to hide in a DOM vector.
            if page.get("injection", "").strip():
                try:
                    html_content = VECTOR_MAP[chosen_vector]["func"](html_content, page["injection"])
                    injection_applied = True
                except Exception as e:
                    logging.error(f"PROMPT INJECTION FAILED | id={page['id']} | vector={chosen_vector} | error={e}")
            logging.info(
                f"REQUEST | path={path} | slug={slug} | id={page['id']} | vector={chosen_vector} | "
                f"injected={injection_applied} | attack_goal={page['attack_goal']!r}"
            )
            self._respond(html_content)
            return

        # ── Original mock-catalog routes (query-param vector injection) ───────
        if path == "/about":
            html_content = self._build_about()
        elif path == "/support":
            html_content = self._build_support()
        else:
            html_content = self._build_catalog()

        # Apply injection if valid vector and payload present
        injection_applied = False
        if vector_id and vector_id in VECTOR_MAP and raw_payload:
            injection_func = VECTOR_MAP[vector_id]["func"]
            try:
                html_content = injection_func(html_content, raw_payload)
                injection_applied = True
            except Exception as e:
                logging.error(f"INJECTION FAILED | vector={vector_id} | error={e}")

        # Server-side ground truth log
        logging.info(
            f"REQUEST | path={path} | vector={vector_id} | "
            f"injected={injection_applied} | payload_preview={raw_payload[:80]!r}"
        )

        self._respond(html_content)

    def _respond(self, html_content, status=200):
        self.send_response(status)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def log_message(self, format, *args):
        pass  # Suppress default stdout noise; we use logging module instead


def get_local_ip():
    """Fetches the local machine's LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


if __name__ == "__main__":
    display_host = get_local_ip() if SERVER_HOST == "0.0.0.0" else SERVER_HOST

    # 1. Safely extract all prompts AND their names/keys from config.py
    available_prompts = []
    if isinstance(INJECTION_PAYLOADS, dict):
        for payload_name, val in INJECTION_PAYLOADS.items():
            if isinstance(val, dict) and "prompt" in val:
                available_prompts.append((payload_name, val["prompt"]))
            elif isinstance(val, str):
                available_prompts.append((payload_name, val))

    # Fallback just in case config is empty
    if not available_prompts:
        available_prompts = [("default_payload", "Missing prompt in config.py!")]

    print(f"🌍 Starting Mock Catalog Server...")
    print(f"📡 Listening on all interfaces (0.0.0.0)")
    print(f"📍 Access locally via: http://localhost:{SERVER_PORT}")
    print(f"🌐 Access on network via: http://{display_host}:{SERVER_PORT}")

    # ONLY showing the catalog route
    routes = ["/catalog"]

    print("\n" + "=" * 90)
    print(" 🔗 FULL INJECTION MATRIX: EVERY VECTOR x EVERY PAYLOAD")
    print("=" * 90)

    print("\n📄 Standard Page (No Injection):")
    for route in routes:
        print(f"   http://{display_host}:{SERVER_PORT}{route}")

    print("\n🎯 Injection Vectors:")
    if VECTOR_MAP:
        for vector_id in VECTOR_MAP.keys():
            print(f"\n   --- Vector: {vector_id} ---")

            # Loop through EVERY payload for THIS specific vector
            for payload_name, raw_payload in available_prompts:
                # URL-encode the payload
                safe_payload = urllib.parse.quote(str(raw_payload))

                for route in routes:
                    url = f"http://{display_host}:{SERVER_PORT}{route}?vector={vector_id}&payload={safe_payload}"
                    print(f"   [{payload_name}] {url}")
    else:
        print("   (No vectors found in VECTOR_MAP)")

    # ── Prompt pages (one per evaluate_defense.py attack case) ───────────────
    print("\n" + "=" * 90)
    print(f" 📑 PROMPT PAGES (imported from evaluate_defense.py) — hidden via '{DEFAULT_PROMPT_VECTOR}'")
    print("=" * 90)
    print(f"\n   Public index: http://{display_host}:{SERVER_PORT}/prompts")
    print("   (append ?vector=<id> to any page to change the stealth vector)")
    print("\n   slug -> attack mapping (operator ground truth; not shown on the site):\n")
    for p in PROMPT_PAGES:
        print(f"   /p/{p['slug']:<28} id={p['id']:<28} [{p['family']:<20}] {p['attack_goal']}")

    print("\n" + "=" * 90)
    print("Press Ctrl+C to shut it down.\n")

    server = http.server.HTTPServer((SERVER_HOST, SERVER_PORT), VulnerableSiteHandler)
    server.serve_forever()