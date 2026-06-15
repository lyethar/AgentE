"""
Stage 1 — Subdomain Enumeration
Tools: subfinder, subscraper, bbot
Runs all three in parallel, deduplicates results, writes merged output.
"""
import asyncio
import logging
import re
from pathlib import Path

from utils.runner import ToolResult, run_parallel, run_tool

log = logging.getLogger("agente.subdomains")

_SUBDOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)


def _parse_subdomains(text: str, domain: str) -> set[str]:
    found = set()
    for line in text.splitlines():
        line = line.strip().lower()
        # strip http(s):// prefixes that some tools emit
        line = re.sub(r"^https?://", "", line).split("/")[0].split(":")[0]
        if line.endswith(f".{domain}") or line == domain:
            if _SUBDOMAIN_RE.match(line):
                found.add(line)
    return found


async def run_subfinder(domain: str, outdir: Path, cfg: dict) -> ToolResult:
    out_file = outdir / "subfinder.txt"
    cmd = [
        "subfinder",
        "-d", domain,
        "-o", str(out_file),
        "-silent",
        "-all",
        *cfg.get("extra_args", []),
    ]
    return await run_tool(cmd, "subfinder", timeout=cfg.get("timeout"))


async def run_subscraper(domain: str, outdir: Path, cfg: dict) -> ToolResult:
    out_file = outdir / "subscraper.txt"
    cmd = ["subscraper", "-d", domain, "-o", str(out_file), *cfg.get("extra_args", [])]
    return await run_tool(cmd, "subscraper", timeout=cfg.get("timeout"))


async def run_bbot(domain: str, outdir: Path, cfg: dict) -> ToolResult:
    bbot_out = outdir / "bbot_output"
    cmd = [
        "bbot",
        "-t", domain,
        "-p", "subdomain-enum", "web-basic", "code-enum", "cloud-enum", "email-enum", "web-screenshots",
        "-o", str(bbot_out),
        "--silent",
        *cfg.get("extra_args", []),
    ]
    return await run_tool(cmd, "bbot", timeout=cfg.get("timeout"))


def _parse_bbot_output(outdir: Path, domain: str) -> set[str]:
    subs: set[str] = set()
    bbot_dir = outdir / "bbot_output"
    # bbot writes subdomains.txt inside its output dir
    candidates = list(bbot_dir.rglob("subdomains.txt")) if bbot_dir.exists() else []
    for f in candidates:
        subs |= _parse_subdomains(f.read_text(errors="replace"), domain)
    return subs


async def enumerate_subdomains(domain: str, outdir: Path, cfg: dict) -> dict:
    log.info("=== Stage 1: Subdomain Enumeration ===")
    sub_cfg = cfg.get("subdomains", {})

    results: list[ToolResult] = await run_parallel(
        run_subfinder(domain, outdir, sub_cfg.get("subfinder", {})),
        run_subscraper(domain, outdir, sub_cfg.get("subscraper", {})),
        run_bbot(domain, outdir, sub_cfg.get("bbot", {})),
        max_concurrency=3,
    )

    by_tool: dict[str, set[str]] = {}

    # subfinder
    r_sf = results[0]
    sf_file = outdir / "subfinder.txt"
    if not r_sf.skipped and sf_file.exists():
        by_tool["subfinder"] = _parse_subdomains(sf_file.read_text(errors="replace"), domain)
    elif not r_sf.skipped:
        by_tool["subfinder"] = _parse_subdomains(r_sf.stdout, domain)
    else:
        by_tool["subfinder"] = set()

    # subscraper
    r_ss = results[1]
    ss_file = outdir / "subscraper.txt"
    if not r_ss.skipped and ss_file.exists():
        by_tool["subscraper"] = _parse_subdomains(ss_file.read_text(errors="replace"), domain)
    elif not r_ss.skipped:
        by_tool["subscraper"] = _parse_subdomains(r_ss.stdout, domain)
    else:
        by_tool["subscraper"] = set()

    # bbot
    by_tool["bbot"] = _parse_bbot_output(outdir, domain) if not results[2].skipped else set()

    all_subs: set[str] = set().union(*by_tool.values())

    merged_file = outdir / "subdomains_all.txt"
    merged_file.write_text("\n".join(sorted(all_subs)), encoding="utf-8")

    log.info(
        "Subdomains: subfinder=%d  subscraper=%d  bbot=%d  total=%d",
        len(by_tool["subfinder"]), len(by_tool["subscraper"]),
        len(by_tool["bbot"]), len(all_subs),
    )

    return {
        "all": sorted(all_subs),
        "by_tool": {k: sorted(v) for k, v in by_tool.items()},
        "merged_file": str(merged_file),
        "tool_results": [
            {"tool": r.tool, "duration": r.duration, "skipped": r.skipped, "skip_reason": r.skip_reason}
            for r in results
        ],
    }
