#!/usr/bin/env python3
"""
AgentE — Enumeration Orchestrator
Authorized security reconnaissance workflow.

Usage:
  python orchestrator.py -d example.com
  python orchestrator.py -d example.com -c "Acme Corp" --stages 1,2,3
  python orchestrator.py -d example.com --config my_config.yaml -v
"""
import argparse
import asyncio
import json
import subprocess
import sys
import time

# Ensure UTF-8 output on Windows consoles that default to CP1252
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
from datetime import datetime
from pathlib import Path

import yaml

from modules.cloud      import enumerate_cloud
from modules.collector  import collect_assets
from modules.email_enum import enumerate_emails
from modules.exposure   import enumerate_exposure
from modules.ip_resolve import resolve_ips
from modules.js_enum    import enumerate_js
from modules.reporting  import generate_report
from modules.subdomains import enumerate_subdomains
from modules.validation import validate_subdomains
from utils.logger       import setup_logger
from utils.runner       import progress_monitor

BANNER = r"""
  ___                    _   _____
 / _ \                  | | |  ___|
/ /_\ \ __ _  ___ _ __ | |_| |__
|  _  |/ _` |/ _ \ '_ \| __|  __|
| | | | (_| |  __/ | | | |_| |___
\_| |_/\__, |\___|_| |_|\__\____/
        __/ |   Enumeration Orchestrator
       |___/    github.com/lyethar/AgentE
"""

ALL_STAGES = [1, 2, 3, 4, 5, 6, 7, 8]

# Maps each tool binary to the stage that uses it and an install hint.
# Stage 4 (asset collection) uses the bundled 'requests' library plus an
# optional Prettier (npx) for formatting, so it has no required pre-flight entry.
TOOL_MANIFEST: list[dict] = [
    # stage, binary, install hint
    {"stage": 1, "bin": "subfinder",        "hint": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    {"stage": 1, "bin": "subscraper",       "hint": "pip install subscraper  OR  https://github.com/m8r0wn/subscraper"},
    {"stage": 1, "bin": "bbot",             "hint": "pip install bbot"},
    {"stage": 2, "bin": "dnsgen",           "hint": "pip install dnsgen"},
    {"stage": 2, "bin": "puredns",          "hint": "go install github.com/d3mondev/puredns/v2@latest"},
    {"stage": 2, "bin": "httpx",            "hint": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    {"stage": 3, "bin": "gospider",         "hint": "go install github.com/jaeles-project/gospider@latest"},
    {"stage": 3, "bin": "katana",           "hint": "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
    {"stage": 5, "bin": "cloud_enum",       "hint": "pip install cloud-enum  OR  https://github.com/initstring/cloud_enum"},
    {"stage": 5, "bin": "pycroburst",        "hint": "python install_tools.py pycroburst",        "managed": True},
    {"stage": 6, "bin": "linkedin2username", "hint": "python install_tools.py linkedin2username",   "managed": True},
    {"stage": 7, "bin": "gitminer3",        "hint": "python install_tools.py gitminer3",          "managed": True},
    # Google dorking (stage 7) uses Playwright (a Python package, not a PATH
    # binary): pip install playwright && playwright install chromium
]


def tool_preflight(stages: set[int], skip_missing: bool = False) -> bool:
    """
    Check that every tool required by the selected stages is in PATH.
    Prints a formatted table; returns True if all required tools are present
    (or if the user chooses to continue with missing ones when skip_missing=False).
    Returns False if any required tool is absent and skip_missing is False.
    """
    from utils.runner import check_tool

    required = [t for t in TOOL_MANIFEST if t["stage"] in stages]
    if not required:
        return True

    present  = [t for t in required if check_tool(t["bin"])]
    missing  = [t for t in required if not check_tool(t["bin"])]

    col_w = max(len(t["bin"]) for t in required) + 2

    print()
    print("  Tool Pre-flight Check")
    print("  " + "-" * (col_w + 22))
    for t in required:
        found = check_tool(t["bin"])
        mark  = "\033[32m[+]\033[0m" if found else "\033[31m[-]\033[0m"
        stage_label = f"stage {t['stage']}"
        print(f"  {mark}  {t['bin']:<{col_w}} {stage_label}")
    print("  " + "-" * (col_w + 22))
    print(f"  Found: {len(present)}/{len(required)}  |  Missing: {len(missing)}")

    if missing:
        print()
        # Split into auto-installable vs manual
        managed = [t for t in missing if t.get("managed")]
        manual  = [t for t in missing if not t.get("managed")]

        if managed:
            print("  \033[36mAuto-installable (git clone + pip):\033[0m")
            for t in managed:
                print(f"    {t['bin']:<{col_w}} {t['hint']}")
            print(f"\n  Run \033[1mpython install_tools.py\033[0m to install all at once.\n")

        if manual:
            print("  \033[33mInstall manually:\033[0m")
            for t in manual:
                print(f"    {t['bin']:<{col_w}} {t['hint']}")
        print()

        if skip_missing:
            print("  \033[33m[!] Continuing — missing tools will be skipped at runtime.\033[0m\n")
            return True

        # Interactive prompt only when stdin is a TTY
        if sys.stdin.isatty():
            try:
                answer = input("  Continue anyway? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = "n"
            print()
            if answer not in ("y", "yes"):
                print("  Aborted. Install the missing tools and re-run.\n")
                return False
            print("  \033[33m[!] Continuing — missing tools will be skipped at runtime.\033[0m\n")
            return True
        else:
            # Non-interactive (CI / piped): fail hard so pipelines catch it
            print("  \033[31m[!] Non-interactive mode — aborting on missing tools.\033[0m")
            print("  Pass --skip-missing to override.\n")
            return False

    print()
    return True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="AgentE — Agentic Enumeration Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-d", "--domain",   required=True,  help="Target domain (e.g. example.com)")
    p.add_argument("-c", "--company",  default="",     help="Company name for LinkedIn enumeration")
    p.add_argument("-i", "--ip-list",  default="",
                   help="Optional file of IPs/CIDRs to reverse-resolve and validate (FQDN/FCrDNS)")
    p.add_argument("--config",         default="config.yaml", help="Path to config.yaml")
    p.add_argument("--stages",         default="1,2,3,4,5,6,7,8",
                   help="Comma-separated stages: 1=subs,2=validate,3=js,4=collect,"
                        "5=cloud,6=email,7=exposure,8=report")
    p.add_argument("-o", "--output",      default="",  help="Override output directory")
    p.add_argument("-v", "--verbose",     action="store_true")
    p.add_argument("--skip-missing",      action="store_true",
                   help="Continue even when required tools are not installed")
    p.add_argument("--check-tools",       action="store_true",
                   help="Run the tool pre-flight check and exit (no scan)")
    p.add_argument("--install-tools",     action="store_true",
                   help="Run install_tools.py for all managed tools, then exit")
    return p.parse_args()


def load_config(path: str) -> dict:
    cfg_path = Path(path)
    if not cfg_path.exists():
        return {}
    with open(cfg_path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def prepare_output_dir(domain: str, cfg: dict, override: str = "") -> Path:
    base = Path(override) if override else Path(cfg.get("global", {}).get("output_base", "output"))
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = base / domain / ts
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


async def run(args: argparse.Namespace, cfg: dict, log) -> int:
    stages = set(int(s.strip()) for s in args.stages.split(",") if s.strip())
    domain  = args.domain.lower().strip()
    company = args.company or domain.split(".")[0]

    outdir = prepare_output_dir(domain, cfg, args.output)
    log.info("Output directory: %s", outdir)

    # Persist config snapshot
    (outdir / "config_snapshot.yaml").write_text(
        yaml.dump(cfg, default_flow_style=False), encoding="utf-8"
    )

    sub_data   = {"all": [], "by_tool": {}, "merged_file": "", "tool_results": []}
    val_data   = {"resolved_subdomains": [], "live_hosts": [], "live_urls": [],
                  "urls_file": "", "resolved_file": "", "tool_results": []}
    js_data    = {"endpoints": [], "js_files": [], "api_paths": [],
                  "potential_secrets": [], "tool_results": []}
    collect_data = {"root": "", "counts": {"downloaded": 0, "skipped": 0, "failed": 0},
                    "by_asset": {}, "total_urls": 0, "js_count": 0,
                    "manifest": [], "tool_results": []}
    cloud_data = {"assets": {}, "total": 0, "tool_results": []}
    email_data = {"emails": [], "usernames": [], "tool_results": []}
    ip_data    = {"results": [], "errors": [], "total_ips": 0, "resolved": 0,
                  "fqdns": [], "validated_fqdns": [], "tool_results": []}
    exposure_data = {"leakix": {"results": [], "count": 0},
                     "gitminer": {"findings": [], "count": 0},
                     "google_dorks": {"findings": [], "count": 0, "dorks_total": 0},
                     "total": 0, "tool_results": []}

    t0 = time.monotonic()

    # Background heartbeat: report which tools are still executing. Tools run
    # without a forced timeout (see config), so this is how long-running tools
    # stay observable while a stage waits for them to finish.
    interval = cfg.get("global", {}).get("progress_interval", 30)
    monitor_task = asyncio.create_task(progress_monitor(interval))

    # ── Optional pre-step: IP → FQDN resolution (--ip-list) ──
    if args.ip_list:
        ip_data = await resolve_ips(Path(args.ip_list), outdir, cfg)

    # ── Stage 1: Subdomains ──
    if 1 in stages:
        sub_data = await enumerate_subdomains(domain, outdir, cfg)

    # Fold IP-derived (FCrDNS-validated) FQDNs into the subdomain pool so they
    # flow through validation / crawling and appear in the report.
    new_fqdns = ip_data.get("validated_fqdns", [])
    if new_fqdns and cfg.get("ip_resolve", {}).get("feed_subdomains", True):
        combined = sorted(set(sub_data.get("all", [])) | set(new_fqdns))
        added = len(combined) - len(set(sub_data.get("all", [])))
        sub_data["all"] = combined
        sub_data.setdefault("by_tool", {})["ptr"] = sorted(
            set(sub_data.get("by_tool", {}).get("ptr", [])) | set(new_fqdns)
        )
        merged = Path(sub_data.get("merged_file") or (outdir / "subdomains_all.txt"))
        existing = set(merged.read_text(errors="replace").split()) if merged.exists() else set()
        merged.write_text("\n".join(sorted(existing | set(combined))), encoding="utf-8")
        sub_data["merged_file"] = str(merged)
        log.info("Merged %d IP-derived FQDN(s) into the subdomain pool", added)

    # ── Stage 2: Validation (depends on Stage 1) ──
    if 2 in stages:
        subs_file = Path(sub_data.get("merged_file", ""))
        if not subs_file.exists():
            # create a placeholder so puredns/httpx still run with empty input
            subs_file = outdir / "subdomains_all.txt"
            subs_file.write_text("", encoding="utf-8")
        val_data = await validate_subdomains(subs_file, outdir, cfg)

    # ── Stage 3: JS Enumeration (depends on Stage 2) ──
    if 3 in stages:
        urls_file = Path(val_data.get("urls_file", ""))
        if not urls_file.exists():
            urls_file = outdir / "live_urls.txt"
            urls_file.write_text("", encoding="utf-8")
        js_data = await enumerate_js(urls_file, outdir, cfg)

    # ── Stage 4: Asset Collection & JS Download (depends on Stage 3) ──
    if 4 in stages:
        collect_data = await collect_assets(outdir, cfg, js_data)

    # ── Stage 5 & 6 run in parallel (independent of each other) ──
    async def _cloud():
        return await enumerate_cloud(domain, outdir, cfg) if 5 in stages else cloud_data

    async def _email():
        return await enumerate_emails(domain, company, outdir, cfg) if 6 in stages else email_data

    cloud_data, email_data = await asyncio.gather(_cloud(), _email())

    # ── Stage 7: Exposure & Secrets Discovery (LeakIX, Gitminer3, Google dorks) ──
    if 7 in stages:
        exposure_data = await enumerate_exposure(domain, company, outdir, cfg)

    # ── Stage 8: Report ──
    if 8 in stages:
        report_path = generate_report(
            domain, outdir, sub_data, val_data, js_data,
            collect_data, cloud_data, email_data, exposure_data, ip_data,
        )
        log.info("HTML report: file://%s", report_path.resolve())

    # Stop the progress heartbeat now that all stages are done.
    monitor_task.cancel()
    try:
        await monitor_task
    except asyncio.CancelledError:
        pass

    elapsed = time.monotonic() - t0

    sep = "-" * 60
    # Print summary
    print()
    print(sep)
    print(f"  Target      : {domain}")
    if args.ip_list:
        print(f"  IPs resolved: {ip_data.get('resolved', 0)}/{ip_data.get('total_ips', 0)} "
              f"(validated FQDNs: {len(ip_data.get('validated_fqdns', []))})")
    print(f"  Subdomains  : {len(sub_data['all'])}")
    print(f"  Live hosts  : {len(val_data['live_hosts'])}")
    print(f"  Endpoints   : {len(js_data['endpoints'])}")
    print(f"  JS collected: {collect_data['counts'].get('downloaded', 0)} "
          f"(across {len(collect_data['by_asset'])} assets)")
    print(f"  Cloud assets: {cloud_data['total']}")
    print(f"  Emails      : {len(email_data['emails'])}")
    print(f"  Exposures   : {exposure_data.get('total', 0)} "
          f"(leakix={exposure_data.get('leakix', {}).get('count', 0)} "
          f"github={exposure_data.get('gitminer', {}).get('count', 0)} "
          f"gdork={exposure_data.get('google_dorks', {}).get('count', 0)})")
    print(f"  Secrets     : {len(js_data.get('potential_secrets', []))}")
    print(f"  Duration    : {elapsed:.1f}s")
    print(f"  Output      : {outdir}")
    print(sep)

    # Write JSON summary for programmatic consumption
    summary = {
        "target":      domain,
        "timestamp":   datetime.now().isoformat(),
        "duration_s":  round(elapsed, 2),
        "stats": {
            "ips_total":      ip_data.get("total_ips", 0),
            "ips_resolved":   ip_data.get("resolved", 0),
            "ip_fqdns_validated": len(ip_data.get("validated_fqdns", [])),
            "subdomains":     len(sub_data["all"]),
            "live_hosts":     len(val_data["live_hosts"]),
            "endpoints":      len(js_data["endpoints"]),
            "files_collected": collect_data["counts"].get("downloaded", 0),
            "js_formatted":   collect_data.get("prettier", {}).get("formatted", 0),
            "assets":         len(collect_data["by_asset"]),
            "cloud_assets":   cloud_data["total"],
            "emails":         len(email_data["emails"]),
            "exposures":      exposure_data.get("total", 0),
            "leakix":         exposure_data.get("leakix", {}).get("count", 0),
            "github_leaks":   exposure_data.get("gitminer", {}).get("count", 0),
            "google_hits":    exposure_data.get("google_dorks", {}).get("count", 0),
            "secrets":        len(js_data.get("potential_secrets", [])),
        },
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return 0


def main():
    print(BANNER)
    args = parse_args()
    cfg  = load_config(args.config)

    # Merge CLI output override into config
    if args.output:
        cfg.setdefault("global", {})["output_base"] = args.output

    outdir = prepare_output_dir(args.domain, cfg, args.output)
    log    = setup_logger("agente", outdir, verbose=args.verbose)

    if args.install_tools:
        rc = subprocess.run([sys.executable, "install_tools.py"]).returncode
        sys.exit(rc)

    stages = set(int(s.strip()) for s in args.stages.split(",") if s.strip())

    if not tool_preflight(stages, skip_missing=args.skip_missing):
        sys.exit(1)

    if args.check_tools:
        sys.exit(0)

    log.info("AgentE starting | target=%s | stages=%s", args.domain, args.stages)

    try:
        rc = asyncio.run(run(args, cfg, log))
        sys.exit(rc)
    except KeyboardInterrupt:
        log.warning("Interrupted by user")
        sys.exit(1)
    except Exception as exc:
        log.exception("Fatal error: %s", exc)
        sys.exit(2)


if __name__ == "__main__":
    main()
