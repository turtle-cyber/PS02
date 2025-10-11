import os
from typing import Dict, Any
from playwright.sync_api import sync_playwright
from fcrawler.utils.io import save_html, screenshot_path
from fcrawler.utils.config import CFG

NAV_TIMEOUT_MS = lambda: int(os.getenv("NAV_TIMEOUT_MS", str(CFG.nav_timeout_ms)))
HEADLESS = os.getenv("PLAYWRIGHT_HEADLESS", "1") == "1"

def navigate_and_capture(url: str) -> Dict[str, Any]:
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=HEADLESS, args=["--no-sandbox"])
        context = browser.new_context(ignore_https_errors=True, user_agent=CFG.user_agent or None)
        page = context.new_page()
        status = None
        final_url = url
        title = None
        try:
            resp = page.goto(url, timeout=NAV_TIMEOUT_MS(), wait_until="load")
            if resp:
                status = resp.status
            final_url = page.url
            title = page.title()
            shot_path = screenshot_path(final_url)
            page.screenshot(path=shot_path, full_page=CFG.screenshot_full_page)
            html = page.content()
            html_path = save_html(final_url, html)
        finally:
            context.close()
            browser.close()
    return {
        "final_url": final_url,
        "status": status,
        "title": title,
        "html_path": html_path,
        "screenshot_path": shot_path,
    }
