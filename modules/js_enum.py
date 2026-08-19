"""
Stage 4 — Client-Side JavaScript & Endpoint Enumeration (Crawl)
Tools: GoSpider, Katana, waymore (run in parallel)
Extracts URLs, JS files, API paths, secrets from crawled pages and from
historical (Wayback / archive) data via waymore. JavaScript files discovered
here are flagged so Stage 5 downloads them and Stage 6 analyses them.
"""
import logging
import re
from pathlib import Path

from utils.runner import ToolResult, run_parallel, run_tool

log = logging.getLogger("agente.js_enum")

_URL_RE    = re.compile(r"https?://[^\s\"'>]+")
_JS_RE     = re.compile(r"https?://[^\s\"'>]+\.js(?:\?[^\s\"'>]*)?")
_API_RE    = re.compile(r"(?:/api/|/v\d+/|/graphql|/rest/)[^\s\"'>\s]*")
_SECRET_RE = re.compile(
    r"(?:api[_-]?key|secret|token|password|passwd|auth|bearer|private)[^\n]{0,120}",
    re.I,
)


async def run_gospider(urls_file: Path, outdir: Path, cfg: dict) -> ToolResult:
    gs_out = outdir / "gospider"
    gs_out.mkdir(exist_ok=True)
    cmd = [
        "gospider",
        "-S", str(urls_file),
        "-o", str(gs_out),
        "--js",
        "--sitemap",
        "--robots",
        "-t", str(cfg.get("threads", 10)),
        "-d", str(cfg.get("depth", 3)),
        "-c", str(cfg.get("concurrent", 5)),
        "--timeout", str(cfg.get("timeout_per_req", 15)),
        *cfg.get("extra_args", []),
    ]
    return await run_tool(cmd, "gospider", timeout=cfg.get("timeout"))


async def run_katana(urls_file: Path, outdir: Path, cfg: dict) -> ToolResult:
    out_file = outdir / "katana.txt"
    cmd = [
        "katana",
        "-list", str(urls_file),
        "-o", str(out_file),
        "-js-crawl",
        "-known-files", "all",
        "-automatic-form-fill",
        "-depth", str(cfg.get("depth", 3)),
        "-concurrency", str(cfg.get("concurrency", 10)),
        "-timeout", str(cfg.get("timeout_per_req", 15)),
        "-silent",
        *cfg.get("extra_args", []),
    ]
    return await run_tool(cmd, "katana", timeout=cfg.get("timeout"))


async def run_waymore(domain: str, outdir: Path, cfg: dict) -> ToolResult:
    """Pull historical/archived URLs for the apex domain (Wayback, etc.)."""
    out_file = outdir / "waymore-urs.txt"
    cmd = [
        "waymore",
        "-i", domain,
        "-mode", cfg.get("mode", "U"),
        "-oU", str(out_file),
        *cfg.get("extra_args", []),
    ]
    # waymore hits several archive APIs and can run long — honour config timeout
    # (default: none), never killed early otherwise.
    return await run_tool(cmd, "waymore", cwd=outdir, timeout=cfg.get("timeout"))


def _collect_waymore_urls(outdir: Path) -> set[str]:
    wm_file = outdir / "waymore-urs.txt"
    if not wm_file.exists():
        return set()
    return {
        line.strip()
        for line in wm_file.read_text(errors="replace").splitlines()
        if line.strip().startswith(("http://", "https://"))
    }


def _collect_gospider_urls(outdir: Path) -> set[str]:
    gs_dir = outdir / "gospider"
    urls: set[str] = set()
    if not gs_dir.exists():
        return urls
    for f in gs_dir.iterdir():
        if f.is_file():
            for line in f.read_text(errors="replace").splitlines():
                # gospider output: [spider] [source_url] - url
                parts = line.split(" - ")
                url = parts[-1].strip() if parts else ""
                if _URL_RE.match(url):
                    urls.add(url)
    return urls


def _collect_katana_urls(outdir: Path) -> set[str]:
    katana_file = outdir / "katana.txt"
    if not katana_file.exists():
        return set()
    return {
        line.strip()
        for line in katana_file.read_text(errors="replace").splitlines()
        if _URL_RE.match(line.strip())
    }


def _analyze_urls(urls: set[str]) -> dict:
    js_files  = {u for u in urls if _JS_RE.search(u)}
    api_paths = {m.group() for u in urls for m in [_API_RE.search(u)] if m}
    return {
        "total":     len(urls),
        "js_files":  sorted(js_files),
        "api_paths": sorted(api_paths),
    }


def _extract_secrets(outdir: Path) -> list[dict]:
    hits: list[dict] = []
    for f in outdir.rglob("*"):
        if not f.is_file():
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for match in _SECRET_RE.finditer(text):
            snippet = match.group()[:200].strip()
            hits.append({"file": str(f.relative_to(outdir)), "snippet": snippet})
    return hits


async def enumerate_js(domain: str, urls_file: Path, outdir: Path, cfg: dict) -> dict:
    log.info("=== Stage 4: JS & Endpoint Enumeration (Crawl) ===")
    js_cfg = cfg.get("js_enum", {})
    waymore_cfg = js_cfg.get("waymore", {})
    waymore_enabled = waymore_cfg.get("enabled", True)

    have_live = urls_file.exists() and urls_file.stat().st_size

    # GoSpider / Katana need live URLs; waymore only needs the apex domain, so it
    # still runs even when there are no live hosts to crawl.
    coros = []
    if have_live:
        coros.append(run_gospider(urls_file, outdir, js_cfg.get("gospider", {})))
        coros.append(run_katana(urls_file, outdir, js_cfg.get("katana", {})))
    else:
        log.warning("No live URLs file — skipping GoSpider/Katana (waymore still runs)")
    if waymore_enabled:
        coros.append(run_waymore(domain, outdir, waymore_cfg))

    results: list[ToolResult] = await run_parallel(*coros, max_concurrency=3) if coros else []

    gs_urls  = _collect_gospider_urls(outdir)
    kat_urls = _collect_katana_urls(outdir)
    wm_urls  = _collect_waymore_urls(outdir) if waymore_enabled else set()
    all_urls = gs_urls | kat_urls | wm_urls

    analysis = _analyze_urls(all_urls)
    # JS files found only in the historical (waymore) data — flagged separately
    # so the report can highlight them; they still feed the shared js_files list.
    waymore_js = sorted(u for u in wm_urls if _JS_RE.search(u))

    secrets  = _extract_secrets(outdir / "gospider") if (outdir / "gospider").exists() else []

    # persist merged endpoint list (drives Stage 5 asset collection)
    ep_file = outdir / "endpoints_all.txt"
    ep_file.write_text("\n".join(sorted(all_urls)), encoding="utf-8")

    log.info(
        "Endpoints: gospider=%d  katana=%d  waymore=%d  total=%d  js_files=%d "
        "(waymore_js=%d)  api_paths=%d",
        len(gs_urls), len(kat_urls), len(wm_urls), len(all_urls),
        len(analysis["js_files"]), len(waymore_js), len(analysis["api_paths"]),
    )

    return {
        "endpoints":         sorted(all_urls),
        "js_files":          analysis["js_files"],
        "api_paths":         analysis["api_paths"],
        "waymore_urls":      sorted(wm_urls),
        "waymore_js":        waymore_js,
        "potential_secrets": secrets[:50],   # cap to avoid huge reports
        "endpoints_file":    str(ep_file),
        "tool_results": [
            {"tool": r.tool, "duration": r.duration, "skipped": r.skipped, "skip_reason": r.skip_reason}
            for r in results
        ],
    }
