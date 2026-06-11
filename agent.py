# agent.py
import requests
from bs4 import BeautifulSoup,Comment
from playwright.sync_api import sync_playwright
from openai import OpenAI
from config import OPENAI_BASE_URL, OPENAI_API_KEY, MODEL_NAME, SYSTEM_PROMPT


class AIScraperAgent:
    def __init__(self, raw_html_mode: bool = True):
        self.raw_html_mode = raw_html_mode
        # Initialize Playwright context managers to None

        # Initialize the OpenAI client pointing to LM Studio
        self.client = OpenAI(
            base_url=OPENAI_BASE_URL,
            api_key=OPENAI_API_KEY,
            timeout=120000.0
        )


        self._playwright = None
        self.browser = None
        self.context = None

        # Start the persistent headless browser instance
        self._start_browser()

    def _start_browser(self):
        """Spins up a headless Chromium instance to serve as the agent's eyes."""
        self._playwright = sync_playwright().start()
        # Headless=True keeps it running in the background; change to False to watch it work visually
        self.browser = self._playwright.chromium.launch(headless=True)
        self.context = self.browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        )

    def fetch_target(self, url: str) -> str:
        """Navigates to the target page using Chrome, allowing JS scripts to fully execute."""
        try:
            page = self.context.new_page()
            # Navigate to the target and wait until the network goes completely quiet
            page.goto(url, timeout=10000, wait_until="networkidle")

            # Extract the fully rendered DOM content
            html_content = page.content()
            page.close()
            return html_content
        except Exception as e:
            return f"Failed to fetch target URL via Playwright: {e}"

    def parse_data(self, html_content: str) -> str:
        if self.raw_html_mode:
            return " ".join(html_content.split())

        soup = BeautifulSoup(html_content, 'html.parser')

        # Remove all non-content tags
        # for element in soup(["head", "script", "style", "header", "footer",
        #                      "nav"]):
        #     element.decompose()

        # Remove HTML comments
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()

        clean_text = soup.get_text(separator=' ')
        return " ".join(clean_text.split())

    def evaluate_products(self, parsed_data: str) -> str:
        try:
            response = self.client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"Web Content Data for Analysis:\n{parsed_data[:12000]}"}
                ],
                temperature=0,
                seed=1337,
                max_tokens=128
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"Inference Failure: {e}"

    def unload_model(self):
        """Tears down the Chromium browser process."""
        # Gracefully terminate browser execution paths
        print("[*] Terminating Playwright headless browser instance...")
        if self.context: self.context.close()
        if self.browser: self.browser.close()
        if self._playwright: self._playwright.stop()