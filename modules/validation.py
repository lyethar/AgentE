"""
Stage 2 — Subdomain Validation
Pipeline: dnsgen (permutation) → puredns (resolve) → httpx (HTTP probe)
"""
import json
import logging
import re
from pathlib import Path

from utils.runner import ToolResult, run_tool

log = logging.getLogger("agente.validation")


async def run_dnsgen(subdomains_file: Path, outdir: Path, cfg: dict) -> ToolResult:
    """Generate permutations from discovered subdomains."""
    out_file = outdir / "dnsgen_out.txt"
    cmd = [
        "dnsgen",
        str(subdomains_file),
        "-w", cfg.get("wordlist", ""),
        *cfg.get("extra_args", []),
    ]
    # remove empty wordlist flag if not configured
    cmd = [c for c in cmd if c]
    result = await run_tool(
        cmd, "dnsgen",
        timeout=cfg.get("timeout"),
    )
    if not result.skipped and result.stdout:
        # dnsgen writes to stdout
        existing = subdomains_file.read_text(errors="replace")
        combined = set(existing.splitlines()) | set(result.stdout.splitlines())
        out_file.write_text("\n".join(sorted(filter(None, combined))), encoding="utf-8")
    else:
        # fallback: just copy the original
        out_file.write_text(subdomains_file.read_text(errors="replace"), encoding="utf-8")
    return result


async def run_puredns(input_file: Path, outdir: Path, cfg: dict) -> ToolResult:
    """Resolve subdomains, write only live ones."""
    out_file = outdir / "resolved_subdomains.txt"
    resolvers = cfg.get("resolvers", "")
    cmd = [
        "puredns", "resolve", str(input_file),
        "-w", str(out_file),
        "--rate-limit", str(cfg.get("rate_limit", 3000)),
        *(["-r", resolvers] if resolvers else []),
        *cfg.get("extra_args", []),
    ]
    return await run_tool(cmd, "puredns", timeout=cfg.get("timeout"))


async def run_httpx(input_file: Path, outdir: Path, cfg: dict) -> ToolResult:
    """Probe live hosts over HTTP/HTTPS, output JSON."""
    out_file = outdir / "httpx.json"
    cmd = [
        "/usr/bin/httpx",
        "-l", str(input_file),
        "-o", str(out_file),
        "-json",
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-follow-redirects",
        "-threads", str(cfg.get("threads", 50)),
        "-timeout", str(cfg.get("probe_timeout", 10)),
        *cfg.get("extra_args", []),
    ]
    return await run_tool(cmd, "httpx", timeout=cfg.get("timeout"))


def _parse_httpx_json(outdir: Path) -> list[dict]:
    httpx_file = outdir / "httpx.json"
    if not httpx_file.exists():
        return []
    hosts = []
    for line in httpx_file.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            hosts.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return hosts


def _extract_urls_from_httpx(hosts: list[dict]) -> list[str]:
    return [h.get("url", "") for h in hosts if h.get("url")]


async def validate_subdomains(
    subdomains_file: Path,
    outdir: Path,
    cfg: dict,
) -> dict:
    log.info("=== Stage 2: Subdomain Validation ===")
    val_cfg = cfg.get("validation", {})

    # Step 1: dnsgen permutations
    dnsgen_result = await run_dnsgen(subdomains_file, outdir, val_cfg.get("dnsgen", {}))

    permuted_file = outdir / "dnsgen_out.txt"
    if not permuted_file.exists():
        permuted_file = subdomains_file
    perm_count = len(permuted_file.read_text(errors="replace").splitlines())
    log.info("dnsgen produced %d candidates", perm_count)

    # Step 2: puredns resolve
    puredns_result = await run_puredns(permuted_file, outdir, val_cfg.get("puredns", {}))

    resolved_file = outdir / "resolved_subdomains.txt"
    if not resolved_file.exists():
        # fallback to original subdomains
        resolved_file = subdomains_file
    resolved = [s.strip() for s in resolved_file.read_text(errors="replace").splitlines() if s.strip()]
    log.info("puredns resolved %d live subdomains", len(resolved))

    # Step 3: httpx probe
    httpx_result = await run_httpx(resolved_file, outdir, val_cfg.get("httpx", {}))
    hosts = _parse_httpx_json(outdir)
    live_urls = _extract_urls_from_httpx(hosts)

    # Write URL list for downstream crawlers
    urls_file = outdir / "live_urls.txt"
    urls_file.write_text("\n".join(live_urls), encoding="utf-8")

    log.info("httpx found %d live HTTP hosts", len(hosts))

    return {
        "resolved_subdomains": resolved,
        "live_hosts": hosts,
        "live_urls": live_urls,
        "urls_file": str(urls_file),
        "resolved_file": str(resolved_file),
        "tool_results": [
            {"tool": r.tool, "duration": r.duration, "skipped": r.skipped, "skip_reason": r.skip_reason}
            for r in [dnsgen_result, puredns_result, httpx_result]
        ],
    }
