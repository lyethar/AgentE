"""
Stage 4 — Asset Collection & JavaScript Download
Runs after GoSpider/Katana (Stage 3). Parses their crawl output, organizes
discovered files into per-asset directories, and downloads every JavaScript
(plus JSON / config) file for later client-side inspection with other tools.

Output layout (under <run>/collected/):
    collected/
      <asset-domain>/
        js/        downloaded *.js
        json/      downloaded *.json
        config/    downloaded config-like files
      asset_manifest.json     machine-readable index of every download
      collected_files.txt     human-readable directory listing

Adapted from the GoSpider JavaScript Extractor download/organize logic. The
heavy security-analysis passes (semgrep, snyk, trufflehog, AI) are intentionally
left out — this stage only *collects* so other tools can inspect later.
"""
import asyncio
import logging
import os
import re
import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger("agente.collector")

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

_URL_RE = re.compile(r"https?://[^\s\"'>]+")


# ──────────────────────────────────────────────────────────────────────────────
# URL classification helpers
# ──────────────────────────────────────────────────────────────────────────────

def _is_downloadable_url(url: str) -> bool:
    """True for .js, .json, or config-like URLs (mirrors the extractor logic)."""
    if not url or url.startswith("javascript:"):
        return False
    path = urlparse(url).path.lower()
    if not path or path == "/":
        return False
    if ".js" in path:
        return True
    if ".json" in path:
        return True
    last = path.split("/")[-1]
    if "/config" in path or path.endswith(".config") or "config." in last:
        return True
    return False


def _file_kind(url: str) -> str:
    """Bucket a URL into 'js' | 'json' | 'config' for directory organization."""
    path = urlparse(url).path.lower()
    if ".js" in path and ".json" not in path:
        return "js"
    if ".json" in path:
        return "json"
    return "config"


def _domain_of(url: str) -> str:
    try:
        netloc = urlparse(url).netloc
        return netloc.split(":")[0] or "unknown"
    except Exception:
        return "unknown"


def _sanitize_filename(url: str) -> str:
    """Safe filename from a URL, preserving .js/.json/.config extensions."""
    path = urlparse(url).path
    if not path or path == "/":
        return "index.js"
    filename = os.path.basename(path)
    allowed = (".js", ".json", ".config")
    if not filename or not any(filename.lower().endswith(e) for e in allowed):
        parts = [p for p in path.split("/") if p]
        ext = ".js"
        if ".json" in path.lower():
            ext = ".json"
        elif "config" in path.lower():
            ext = ".config" if path.lower().endswith(".config") else ".json"
        filename = ("_".join(parts) + ext) if parts else "index.js"
    filename = re.sub(r'[<>:"/\\|?*]', "_", filename)
    return filename[:200]


# ──────────────────────────────────────────────────────────────────────────────
# Source parsers — read GoSpider / Katana / merged output already on disk
# ──────────────────────────────────────────────────────────────────────────────

def _parse_gospider_dir(outdir: Path) -> set[str]:
    """Extract downloadable URLs from GoSpider per-host output files."""
    urls: set[str] = set()
    gs_dir = outdir / "gospider"
    if not gs_dir.exists():
        return urls
    for f in gs_dir.iterdir():
        if not f.is_file():
            continue
        for line in f.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            # [javascript] - URL   and   [url] - [code-200] - URL
            m = re.search(r"\[javascript\]\s*-\s*(\S+)", line)
            if not m:
                m = re.search(r"\[url\]\s*-\s*\[code-\d+\]\s*-\s*(\S+)", line)
            candidate = m.group(1).strip() if m else (line.split(" - ")[-1].strip())
            if candidate and _is_downloadable_url(candidate):
                urls.add(candidate)
    return urls


def _parse_url_list(path: Path) -> set[str]:
    """Extract downloadable URLs from a plain one-URL-per-line file (Katana, merged)."""
    urls: set[str] = set()
    if not path.exists():
        return urls
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("http://", "https://")) and _is_downloadable_url(line):
            urls.add(line)
    return urls


def _gather_download_urls(outdir: Path, js_data: dict) -> set[str]:
    """Union of every downloadable URL from all Stage-3 sources."""
    urls: set[str] = set()
    urls |= _parse_gospider_dir(outdir)
    urls |= _parse_url_list(outdir / "katana.txt")
    urls |= _parse_url_list(outdir / "endpoints_all.txt")
    # Also fold in the js_files list Stage 3 already classified
    for u in js_data.get("js_files", []):
        if _is_downloadable_url(u):
            urls.add(u)
    for u in js_data.get("endpoints", []):
        if _is_downloadable_url(u):
            urls.add(u)
    return urls


# ──────────────────────────────────────────────────────────────────────────────
# Downloader
# ──────────────────────────────────────────────────────────────────────────────

def _build_session(cfg: dict):
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1,
                  status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": cfg.get(
            "user_agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
    })
    return session


def _download_one(session, url: str, dest: Path, timeout: int) -> str:
    """Returns 'downloaded' | 'skipped' | 'failed'."""
    try:
        if dest.exists() and dest.stat().st_size > 0:
            return "skipped"
        dest.parent.mkdir(parents=True, exist_ok=True)
        resp = session.get(url, timeout=timeout, stream=True)
        resp.raise_for_status()
        with open(dest, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=8192):
                fh.write(chunk)
        return "downloaded"
    except Exception:
        # Clean up partial/empty file on failure
        try:
            if dest.exists() and dest.stat().st_size == 0:
                dest.unlink()
        except OSError:
            pass
        return "failed"


# ──────────────────────────────────────────────────────────────────────────────
# Prettier — pretty-print downloaded JavaScript for readable client-side review
# ──────────────────────────────────────────────────────────────────────────────

def _prettier_command() -> list[str] | None:
    """
    Resolve a runnable Prettier invocation:
      1. a globally/locally installed `prettier` binary, else
      2. `npx --yes prettier` (auto-fetches Prettier on first run).
    Returns the base command list, or None if neither npm/npx nor prettier exist.
    """
    direct = shutil.which("prettier")
    if direct:
        return [direct]
    npx = shutil.which("npx")
    if npx:
        return [npx, "--yes", "prettier"]
    return None


def _run_prettier(collected_root: Path, cfg: dict) -> dict:
    """
    Format every downloaded *.js file in-place with Prettier.
    Best-effort: a missing toolchain or a Prettier error never fails the stage.
    """
    pcfg = cfg.get("prettier", {})
    if isinstance(pcfg, bool):          # allow `prettier: true/false` shorthand
        enabled, pcfg = pcfg, {}
    else:
        enabled = pcfg.get("enabled", True)

    info = {"enabled": enabled, "available": False, "formatted": 0,
            "skipped": True, "skip_reason": ""}

    if not enabled:
        info["skip_reason"] = "disabled in config"
        return info

    base = _prettier_command()
    if not base:
        info["skip_reason"] = "prettier/npx not found (npm install -g prettier)"
        log.warning("Collector: Prettier not available — skipping JS formatting "
                    "(install per https://prettier.io/docs/install)")
        return info

    info["available"] = True
    # Prettier prints each rewritten file path to stdout; glob is relative to cwd.
    # No timeout — large/minified bundles can take a while and we let it finish.
    cmd = base + ["--write", "--no-error-on-unmatched-pattern",
                  "--log-level", "warn", "**/*.js"]
    log.info("Collector: formatting downloaded JS with Prettier (no time limit) ...")
    try:
        proc = subprocess.run(
            cmd, cwd=str(collected_root),
            capture_output=True, text=True,
        )
        formatted = sum(
            1 for ln in (proc.stdout or "").splitlines()
            if ln.strip().lower().endswith(".js")
        )
        info["formatted"] = formatted
        info["skipped"] = False
        if proc.returncode != 0 and not formatted:
            info["skip_reason"] = (proc.stderr or "").strip()[:200] or "prettier error"
            log.warning("Collector: Prettier exited %d: %s",
                        proc.returncode, info["skip_reason"])
        else:
            log.info("Collector: Prettier formatted %d JS file(s)", formatted)
    except Exception as exc:
        info["skip_reason"] = str(exc)
        log.warning("Collector: Prettier failed: %s", exc)
    return info


def _collect_blocking(outdir: Path, js_data: dict, cfg: dict) -> dict:
    """Synchronous collection routine (run in a thread from the async stage)."""
    collected_root = outdir / "collected"
    collected_root.mkdir(exist_ok=True)

    urls = _gather_download_urls(outdir, js_data)
    log.info("Collector: %d downloadable URLs (js/json/config) discovered", len(urls))

    # Plan downloads: per-asset, per-kind directory layout
    plan: list[tuple[str, Path, str, str]] = []   # (url, dest, asset, kind)
    for url in sorted(urls):
        asset = _domain_of(url)
        kind = _file_kind(url)
        fname = _sanitize_filename(url)
        dest = collected_root / asset / kind / fname
        plan.append((url, dest, asset, kind))

    counts = {"downloaded": 0, "skipped": 0, "failed": 0}
    manifest: list[dict] = []

    if not plan:
        log.warning("Collector: nothing to download")
    elif not _REQUESTS_AVAILABLE:
        log.warning("Collector: 'requests' not installed — skipping downloads "
                    "(pip install requests). Directory plan still written.")
        for url, dest, asset, kind in plan:
            manifest.append({"url": url, "asset": asset, "kind": kind,
                             "path": str(dest.relative_to(outdir)), "status": "skipped-no-requests"})
    else:
        session = _build_session(cfg)
        workers = int(cfg.get("workers", 10))
        timeout = int(cfg.get("timeout", 30))
        log.info("Collector: downloading with %d workers (timeout=%ds)", workers, timeout)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(_download_one, session, url, dest, timeout): (url, dest, asset, kind)
                for url, dest, asset, kind in plan
            }
            done = 0
            for fut in as_completed(future_map):
                url, dest, asset, kind = future_map[fut]
                status = fut.result()
                counts[status] = counts.get(status, 0) + 1
                manifest.append({"url": url, "asset": asset, "kind": kind,
                                 "path": str(dest.relative_to(outdir)), "status": status})
                done += 1
                if done % 25 == 0 or done == len(plan):
                    log.info("Collector: %d/%d  (ok=%d skip=%d fail=%d)",
                             done, len(plan), counts["downloaded"],
                             counts["skipped"], counts["failed"])

    # Format the downloaded JavaScript so it's readable for client-side review
    js_count = sum(1 for m in manifest if m["kind"] == "js")
    if js_count and counts.get("downloaded", 0):
        prettier_info = _run_prettier(collected_root, cfg)
    else:
        prettier_info = {"enabled": cfg.get("prettier", True) not in (False, {"enabled": False}),
                         "available": False, "formatted": 0, "skipped": True,
                         "skip_reason": "no JavaScript downloaded"}

    # Per-asset aggregation for the report
    by_asset: dict[str, dict] = {}
    for m in manifest:
        a = by_asset.setdefault(m["asset"], {"js": 0, "json": 0, "config": 0, "total": 0})
        a[m["kind"]] += 1
        a["total"] += 1

    # Persist manifest (JSON) + human listing (txt)
    (collected_root / "asset_manifest.json").write_text(
        json.dumps({"counts": counts, "by_asset": by_asset, "files": manifest}, indent=2),
        encoding="utf-8",
    )
    _write_listing(collected_root, by_asset, counts)

    log.info("Collector: assets=%d  js=%d  downloaded=%d  skipped=%d  failed=%d  prettier=%d",
             len(by_asset), js_count, counts["downloaded"], counts["skipped"],
             counts["failed"], prettier_info.get("formatted", 0))

    return {
        "root": str(collected_root),
        "counts": counts,
        "by_asset": by_asset,
        "total_urls": len(urls),
        "js_count": js_count,
        "prettier": prettier_info,
        "manifest": manifest,
        "tool_results": [
            {
                "tool": "collector", "duration": 0.0,
                "skipped": not _REQUESTS_AVAILABLE,
                "skip_reason": "" if _REQUESTS_AVAILABLE else "requests not installed",
            },
            {
                "tool": "prettier", "duration": 0.0,
                "skipped": prettier_info.get("skipped", True),
                "skip_reason": prettier_info.get("skip_reason", ""),
            },
        ],
    }


def _write_listing(root: Path, by_asset: dict, counts: dict) -> None:
    lines = ["Collected Files — Directory Listing (JS / JSON / config)",
             "=" * 60, ""]
    lines.append(f"Downloaded: {counts.get('downloaded', 0)}   "
                 f"Skipped: {counts.get('skipped', 0)}   "
                 f"Failed: {counts.get('failed', 0)}")
    lines.append("")
    for asset in sorted(by_asset):
        a = by_asset[asset]
        lines.append(f"[{asset}]  js={a['js']}  json={a['json']}  config={a['config']}  total={a['total']}")
        asset_dir = root / asset
        if asset_dir.exists():
            for kind_dir in sorted(p for p in asset_dir.iterdir() if p.is_dir()):
                for f in sorted(kind_dir.glob("*")):
                    if f.is_file():
                        size = f.stat().st_size
                        lines.append(f"    {kind_dir.name}/{f.name} ({size:,} bytes)")
        lines.append("")
    (root / "collected_files.txt").write_text("\n".join(lines), encoding="utf-8")


# ──────────────────────────────────────────────────────────────────────────────
# Async entry point
# ──────────────────────────────────────────────────────────────────────────────

async def collect_assets(outdir: Path, cfg: dict, js_data: dict) -> dict:
    log.info("=== Stage 4: Asset Collection & JavaScript Download ===")
    collect_cfg = cfg.get("collect", {})
    # Heavy I/O runs in a worker thread so the event loop stays responsive
    return await asyncio.to_thread(_collect_blocking, outdir, js_data, collect_cfg)
