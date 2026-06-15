"""
Browser-driven Google dorking via Playwright (no Claude / no API key).

Drives a real Chromium instance: for each dork it navigates to Google, handles
the EU consent interstitial, detects CAPTCHA / "unusual traffic" blocks, and
scrapes the organic result anchors. Runs the synchronous Playwright API, which
is safe to call from an `asyncio.to_thread` worker (no event loop in that thread).

Google rate-limits automated searching, so queries are throttled with a random
delay and CAPTCHA'd queries are flagged rather than retried. For long runs,
pointing `user_data_dir` at a real logged-in Chrome profile and/or running
non-headless materially reduces blocking.
"""
import logging
import random
import time
import urllib.parse

log = logging.getLogger("agente.browser_search")

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

    class PWTimeout(Exception):  # type: ignore  # placeholder when missing
        pass


_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# Collect organic result anchors (those wrapping an <h3> title), skipping
# Google's own links and de-duplicating.
_EXTRACT_JS = """
() => {
  const out = [];
  const seen = new Set();
  document.querySelectorAll('a').forEach(a => {
    const h3 = a.querySelector('h3');
    if (!h3) return;
    const href = a.href || '';
    if (!href.startsWith('http')) return;
    let host;
    try { host = new URL(href).hostname; } catch (e) { return; }
    if (host.endsWith('google.com') || host.endsWith('googleusercontent.com')
        || host.endsWith('gstatic.com')) return;
    if (seen.has(href)) return;
    seen.add(href);
    out.push({ url: href, title: (h3.innerText || '').trim() });
  });
  return out;
}
"""


def playwright_available() -> bool:
    return _PLAYWRIGHT_AVAILABLE


def _handle_consent(page) -> None:
    """Dismiss Google's EU cookie-consent interstitial if present."""
    for sel in ("#L2AGLb", "button:has-text('Accept all')",
                "button:has-text('I agree')", "button:has-text('Reject all')"):
        try:
            btn = page.query_selector(sel)
            if btn:
                btn.click()
                page.wait_for_timeout(1000)
                return
        except Exception:
            continue


def _is_blocked(page) -> bool:
    try:
        if "/sorry/" in page.url or "captcha" in page.url.lower():
            return True
        if page.query_selector("form#captcha-form, iframe[src*='recaptcha']"):
            return True
    except Exception:
        pass
    return False


def google_search_batch(queries: list[str], cfg: dict, log_progress=None) -> tuple[list[dict], str]:
    """
    Run every query in `queries` through a real browser.

    Returns (results, error). `error` is non-empty only when the whole batch
    could not start (e.g. Playwright not installed / browser launch failed).
    Each result dict: dork, results_found, top_results, all_results, count, note.
    """
    if not _PLAYWRIGHT_AVAILABLE:
        return [], ("playwright not installed — pip install playwright "
                    "&& playwright install chromium")

    headless      = bool(cfg.get("headless", True))
    min_delay     = float(cfg.get("min_delay", 5))
    max_delay     = float(cfg.get("max_delay", 15))
    nav_timeout   = int(cfg.get("nav_timeout", 30)) * 1000
    user_data_dir = cfg.get("user_data_dir", "") or ""

    results: list[dict] = []

    try:
        pw = sync_playwright().start()
    except Exception as exc:
        return [], f"failed to start Playwright: {str(exc)[:160]}"

    browser = None
    context = None
    try:
        try:
            if user_data_dir:
                context = pw.chromium.launch_persistent_context(
                    user_data_dir, headless=headless, user_agent=_UA,
                    viewport={"width": 1280, "height": 900},
                )
            else:
                browser = pw.chromium.launch(headless=headless)
                context = browser.new_context(
                    user_agent=_UA, viewport={"width": 1280, "height": 900},
                )
        except Exception as exc:
            return [], (f"failed to launch Chromium: {str(exc)[:160]} "
                        "(did you run `playwright install chromium`?)")

        page = context.pages[0] if context.pages else context.new_page()
        total = len(queries)

        for idx, dork in enumerate(queries, 1):
            search_url = "https://www.google.com/search?" + urllib.parse.urlencode(
                {"q": dork, "num": 20, "hl": "en"}
            )
            entry = {"dork": dork, "results_found": False, "top_results": [],
                     "all_results": [], "count": 0, "note": ""}
            try:
                page.goto(search_url, timeout=nav_timeout, wait_until="domcontentloaded")
                if idx == 1:
                    _handle_consent(page)
                    if "consent" in page.url or "consent" in (page.title() or "").lower():
                        page.goto(search_url, timeout=nav_timeout, wait_until="domcontentloaded")
                try:
                    page.wait_for_selector("div#search, div#rso, form#captcha-form",
                                           timeout=8000)
                except PWTimeout:
                    pass
                page.wait_for_timeout(800)

                if _is_blocked(page):
                    entry["note"] = "captcha"
                    log.warning("Google dorks: CAPTCHA/block on query %d/%d", idx, total)
                else:
                    items = page.evaluate(_EXTRACT_JS) or []
                    urls = [it["url"] for it in items if it.get("url")]
                    entry["all_results"] = urls
                    entry["top_results"] = urls[:3]
                    entry["count"] = len(urls)
                    entry["results_found"] = bool(urls)
            except PWTimeout:
                entry["note"] = "timeout"
            except Exception as exc:
                entry["note"] = f"error: {str(exc)[:120]}"

            results.append(entry)
            if log_progress:
                log_progress(idx, total, entry)

            if idx < total:
                time.sleep(random.uniform(min_delay, max_delay))
    finally:
        try:
            if browser is not None:
                browser.close()
            elif context is not None:
                context.close()
        except Exception:
            pass
        try:
            pw.stop()
        except Exception:
            pass

    return results, ""
