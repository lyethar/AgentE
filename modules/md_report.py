"""
Stage 10 (Markdown) — machine-readable findings + an LLM analysis prompt.

Alongside the HTML reports, AgentE writes two Markdown files into ``reports/``:

    findings.md     every stage's findings as plain Markdown, so an LLM (or a
                    human) can read the whole run without opening a browser.
    LLM_PROMPT.md   a ready-to-paste prompt that maps the run's folder layout,
                    the tools that ran, and the key output files, then asks an
                    LLM to suggest additional, prioritised manual testing.

The goal is a hand-off artifact: point an LLM at the run directory with
LLM_PROMPT.md and it can reason about attack surface using findings.md plus the
raw tool output the prompt enumerates.
"""
import logging
from datetime import datetime
from pathlib import Path

log = logging.getLogger("agente.md_report")

_SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


# ──────────────────────────────────────────────────────────────────────────────
# Markdown helpers
# ──────────────────────────────────────────────────────────────────────────────

def _md_escape(text: str) -> str:
    """Escape pipe characters so free text does not break Markdown tables."""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def _table(headers: list[str], rows: list[list], empty: str = "_None._") -> str:
    if not rows:
        return empty + "\n"
    head = "| " + " | ".join(headers) + " |"
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    body = "\n".join("| " + " | ".join(_md_escape(c) for c in r) + " |" for r in rows)
    return f"{head}\n{sep}\n{body}\n"


def _truncate_note(shown: int, total: int, source: str) -> str:
    if total > shown:
        return f"\n_Showing {shown} of {total}. Full list: `{source}`._\n"
    return ""


# ──────────────────────────────────────────────────────────────────────────────
# findings.md sections
# ──────────────────────────────────────────────────────────────────────────────

def _sec_summary(meta: dict, counts: dict) -> str:
    rows = [
        ["Target", meta.get("domain", "")],
        ["Generated", meta.get("timestamp", "")],
        ["Stages run", meta.get("stages", "")],
        ["Subdomains", counts.get("subdomains", 0)],
        ["Live hosts", counts.get("live_hosts", 0)],
        ["Open ports (nmap)", counts.get("open_ports", 0)],
        ["Nuclei findings", counts.get("nuclei", 0)],
        ["Endpoints", counts.get("endpoints", 0)],
        ["JS collected", counts.get("js_collected", 0)],
        ["Secrets (regex+trufflehog)", counts.get("secrets", 0)],
        ["Cloud assets", counts.get("cloud", 0)],
        ["Emails", counts.get("emails", 0)],
        ["Exposures", counts.get("exposures", 0)],
    ]
    return "## Summary\n\n" + _table(["Metric", "Value"], rows)


def _sec_nmap(nmap_data: dict) -> str:
    out = ["## Nmap Port Scan (--ip-list scope)\n"]
    if not nmap_data or not nmap_data.get("enabled"):
        out.append("_Nmap did not run (no `--ip-list` targets, or disabled)._\n")
        return "\n".join(out)
    if nmap_data.get("skipped") and not nmap_data.get("hosts"):
        out.append(f"_Skipped: {nmap_data.get('skip_reason', 'n/a')}._\n")
        return "\n".join(out)

    out.append(f"`{nmap_data.get('open_ports_total', 0)}` open port(s) across "
               f"`{len([h for h in nmap_data.get('hosts', []) if h.get('ports')])}` host(s); "
               f"`{nmap_data.get('hosts_scanned', 0)}` target(s) scanned. "
               "Raw: `03-screenshots/nmap_*.xml` / `.txt`.\n")
    rows = []
    for h in nmap_data.get("hosts", []):
        ip = h.get("ip", "")
        hostname = h.get("hostname", "")
        host_label = f"{ip} ({hostname})" if hostname else ip
        for p in h.get("ports", []):
            product = " ".join(x for x in (p.get("product", ""), p.get("version", ""),
                                           p.get("extrainfo", "")) if x)
            scripts = "; ".join(f"{k}: {v}" for k, v in (p.get("scripts", {}) or {}).items())
            rows.append([host_label, f"{p.get('port','')}/{p.get('proto','')}",
                         p.get("service", ""), product, scripts[:200]])
    out.append(_table(["Host", "Port", "Service", "Product/Version", "Scripts"], rows,
                      empty="_No open ports found._"))
    return "\n".join(out)


def _sec_nuclei(recon_data: dict) -> str:
    findings = recon_data.get("findings", [])
    out = ["## Nuclei Vulnerability Findings\n"]
    counts = recon_data.get("counts", {})
    out.append(f"Total `{counts.get('total', 0)}` — "
               f"critical `{counts.get('critical', 0)}`, high `{counts.get('high', 0)}`, "
               f"medium `{counts.get('medium', 0)}`, low `{counts.get('low', 0)}`, "
               f"info `{counts.get('info', 0)}`. Raw: `03-screenshots/nuclei-results.out`.\n")
    # Group by severity, most severe first.
    by_sev: dict[str, list] = {}
    for f in findings:
        by_sev.setdefault(f.get("severity", "unknown"), []).append(f)
    shown = 0
    for sev in _SEV_ORDER:
        items = by_sev.get(sev, [])
        if not items:
            continue
        out.append(f"### {sev.upper()} ({len(items)})\n")
        rows = [[f.get("template", ""), f.get("url", ""), f.get("extra", "")[:120]]
                for f in items[:50]]
        shown += len(rows)
        out.append(_table(["Template", "URL", "Extracted"], rows))
    if not findings:
        out.append("_No Nuclei findings._\n")
    return "\n".join(out)


def _sec_live_hosts(val_data: dict) -> str:
    hosts = val_data.get("live_hosts", [])
    out = ["## Live Hosts\n"]
    rows = []
    for h in hosts[:100]:
        rows.append([h.get("url", ""), h.get("status_code", ""),
                     (h.get("title", "") or "")[:80],
                     ", ".join(h.get("tech", []) or [])])
    out.append(_table(["URL", "Status", "Title", "Tech"], rows))
    out.append(_truncate_note(min(len(hosts), 100), len(hosts),
                              "02-validation/live_urls.txt"))
    return "\n".join(out)


def _sec_subdomains(sub_data: dict) -> str:
    subs = sorted(sub_data.get("all", []))
    out = ["## Subdomains\n", f"`{len(subs)}` discovered.\n"]
    if subs:
        out.append("```\n" + "\n".join(subs[:200]) + "\n```\n")
        out.append(_truncate_note(min(len(subs), 200), len(subs),
                                  "01-subdomains/subdomains_all.txt"))
    return "\n".join(out)


def _sec_endpoints(js_data: dict) -> str:
    endpoints = js_data.get("endpoints", [])
    js_files = js_data.get("js_files", [])
    api_paths = js_data.get("api_paths", [])
    out = ["## Endpoints & JavaScript\n",
           f"Endpoints `{len(endpoints)}`, JS files `{len(js_files)}`, "
           f"API paths `{len(api_paths)}`, "
           f"waymore URLs `{len(js_data.get('waymore_urls', []))}`. "
           "Raw: `04-crawl/`.\n"]
    if api_paths:
        out.append("### API Paths\n")
        out.append("```\n" + "\n".join(api_paths[:100]) + "\n```\n")
    return "\n".join(out)


def _sec_secrets(secrets_data: dict) -> str:
    counts = secrets_data.get("counts", {})
    out = ["## Secrets & JS Intel\n",
           f"Regex secrets `{counts.get('secrets', 0)}`, "
           f"trufflehog `{counts.get('trufflehog', 0)}` "
           f"(verified `{counts.get('trufflehog_verified', 0)}`), "
           f"endpoints `{counts.get('endpoints', 0)}`. "
           "Details: `reports/secrets.html`, `06-js-analysis/`.\n"]
    manual = secrets_data.get("manual", {}) or {}
    rows = []
    for s in (manual.get("secrets", []) or [])[:50]:
        if isinstance(s, dict):
            # Prefer the masked value so raw secrets are not duplicated into the report.
            value = s.get("masked") or s.get("value", "")
            rows.append([s.get("type", ""), str(value)[:60],
                         s.get("confidence", ""), (s.get("source", "") or "")[:60]])
    if rows:
        out.append(_table(["Type", "Value (masked)", "Confidence", "File"], rows))
    return "\n".join(out)


def _sec_cloud(cloud_data: dict) -> str:
    assets = cloud_data.get("assets", {}) or {}
    out = ["## Cloud Assets\n", f"`{cloud_data.get('total', 0)}` total. Raw: `07-cloud/`.\n"]
    for label, key in [("AWS S3", "s3"), ("Azure Blob", "azure"),
                       ("GCP Storage", "gcp"), ("Functions", "functions")]:
        items = assets.get(key, []) or []
        if items:
            out.append(f"**{label}** ({len(items)})\n")
            out.append("```\n" + "\n".join(str(i) for i in items[:50]) + "\n```\n")
    return "\n".join(out)


def _sec_emails(email_data: dict) -> str:
    emails = email_data.get("emails", [])
    out = ["## Emails & Usernames\n",
           f"Emails `{len(emails)}`, usernames `{len(email_data.get('usernames', []))}`. "
           "Raw: `08-email/`.\n"]
    if emails:
        out.append("```\n" + "\n".join(emails[:100]) + "\n```\n")
    return "\n".join(out)


def _sec_exposure(exposure_data: dict) -> str:
    out = ["## Exposures (LeakIX / GitHub / Google Dorks)\n",
           f"Total `{exposure_data.get('total', 0)}` — "
           f"leakix `{exposure_data.get('leakix', {}).get('count', 0)}`, "
           f"github `{exposure_data.get('gitminer', {}).get('count', 0)}`, "
           f"google `{exposure_data.get('google_dorks', {}).get('count', 0)}`. "
           "Details: `reports/09-exposure.html`, `09-exposure/`.\n"]
    return "\n".join(out)


def _sec_ip(ip_data: dict) -> str:
    if not ip_data.get("total_ips"):
        return ""
    out = ["## IP → FQDN Resolution (--ip-list)\n",
           f"`{ip_data.get('resolved', 0)}/{ip_data.get('total_ips', 0)}` had a PTR; "
           f"`{len(ip_data.get('validated_fqdns', []))}` FCrDNS-validated. "
           "Raw: `00-ip-resolve/`.\n"]
    rows = []
    for r in ip_data.get("results", [])[:100]:
        if not isinstance(r, dict):
            continue
        rows.append([r.get("ip", ""), ", ".join(r.get("fqdns", []) or []),
                     "yes" if r.get("validated") else "no", r.get("status", "")])
    out.append(_table(["IP", "FQDN(s)", "Validated", "Status"], rows))
    return "\n".join(out)


# ──────────────────────────────────────────────────────────────────────────────
# LLM_PROMPT.md
# ──────────────────────────────────────────────────────────────────────────────

# Every stage's directory + the artifacts it produces. Only entries whose path
# exists in the run are listed in the generated prompt.
_ARTIFACT_MAP = [
    ("logs/agente.log", "Full run log — every stage, timestamped."),
    ("logs/commands.log", "Chronological index of EVERY external command run (tool, time, rc, duration)."),
    ("logs/tools/", "One detail file per command: exact invocation + full stdout/stderr."),
    ("summary.json", "Machine-readable run stats."),
    ("config_snapshot.yaml", "Exact config used for this run."),
    ("00-ip-resolve/", "IP→FQDN (PTR/FCrDNS) results for --ip-list inputs."),
    ("01-subdomains/", "Subdomain enumeration output (subfinder/subscraper/bbot)."),
    ("02-validation/live_urls.txt", "Live HTTP(S) URLs after DNS + httpx validation."),
    ("03-screenshots/nmap_fast.xml", "Nmap fast top-ports sweep (XML)."),
    ("03-screenshots/nmap_service_*.xml", "Nmap targeted -sV -sC service/script scans (XML)."),
    ("03-screenshots/nuclei-results.out", "Raw Nuclei findings."),
    ("03-screenshots/screenshots/", "gowitness screenshots of live hosts."),
    ("04-crawl/", "Crawled endpoints, JS files, API paths, waymore archive URLs."),
    ("05-assets/", "Downloaded JS/JSON/config assets for client-side review."),
    ("06-js-analysis/", "semgrep + DOM heuristics + secrets scan output."),
    ("07-cloud/", "Cloud storage/function enumeration."),
    ("08-email/", "Email + LinkedIn username intelligence."),
    ("09-exposure/", "LeakIX / GitHub secret / Google-dork exposure hits."),
    ("reports/index.html", "Executive HTML dashboard (entry point)."),
    ("reports/findings.md", "This run's findings in Markdown (read this first)."),
]


def _build_llm_prompt(meta: dict, run_dir: Path, tool_results: list[dict]) -> str:
    domain = meta.get("domain", "the target")

    # Only list artifacts that actually exist (support globs for nmap service files).
    listed = []
    for rel, desc in _ARTIFACT_MAP:
        if "*" in rel:
            base = run_dir / rel.split("*")[0]
            parent = base.parent
            pattern = base.name + "*"
            if parent.exists() and any(parent.glob(pattern)):
                listed.append((rel, desc))
        elif (run_dir / rel).exists():
            listed.append((rel, desc))
    artifact_lines = "\n".join(f"- `{rel}` — {desc}" for rel, desc in listed)

    # Tools that actually ran (deduped, with status).
    seen: dict[str, dict] = {}
    for r in tool_results:
        seen.setdefault(r.get("tool", "?"), r)
    tool_lines = "\n".join(
        f"- `{t}` — {'skipped' if r.get('skipped') else 'ran'} "
        f"({round(r.get('duration', 0), 1)}s)"
        + (f" — {r.get('skip_reason')}" if r.get("skip_reason") else "")
        for t, r in sorted(seen.items())
    ) or "- (no tool results recorded)"

    return f"""# LLM Analysis Prompt — AgentE recon of `{domain}`

You are a senior offensive-security analyst. AgentE (an authorized enumeration
orchestrator) has completed a reconnaissance run against **{domain}**. Your job
is to read the run's outputs and propose **additional, prioritised manual
testing** — concrete next steps a human pentester should take, grounded in what
was actually found. Do not invent findings; cite the file/finding each
suggestion is based on.

## How this run is organised

The run lives in a single timestamped directory. Key artifacts (only those
present in THIS run are listed):

{artifact_lines}

Numbered folders (`00-` … `09-`) follow the pipeline order. `reports/*.html`
render each stage; `reports/findings.md` is the same data in Markdown.

## Tools executed

{tool_lines}

Every command is recorded verbatim in `logs/commands.log`, with full stdout/stderr
per invocation under `logs/tools/`. Use these to see exactly what ran and with
which flags.

## What to produce

1. **Attack-surface summary** — the most interesting hosts, ports, services,
   endpoints, and exposures, ranked by likely impact.
2. **Prioritised testing plan** — for each item: the target (host/URL/param),
   the technique to try, the tool/command to run, and why (which finding
   motivates it). Prioritise Critical/High Nuclei hits, exposed services from
   the Nmap scan, secrets, and sensitive endpoints.
3. **Gaps** — surface AgentE did NOT cover that a human should (auth flows,
   business logic, chained vulns), and which raw files to inspect for them.

Start by reading `reports/findings.md`, then drill into the raw files above as
needed. Be specific and actionable.
"""


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def generate_markdown(
    domain: str,
    dirs: dict,
    sub_data: dict,
    val_data: dict,
    js_data: dict,
    collect_data: dict,
    cloud_data: dict,
    email_data: dict,
    exposure_data: dict,
    ip_data: dict,
    jsa_data: dict,
    recon_data: dict,
    secrets_data: dict,
    meta: dict | None = None,
) -> Path:
    """
    Write ``reports/findings.md`` and ``reports/LLM_PROMPT.md``. Returns the path
    to findings.md.
    """
    log.info("=== Stage 10: Generating Markdown reports (findings.md + LLM_PROMPT.md) ===")
    reports_dir = Path(dirs["reports"])
    run_dir = Path(dirs["root"])
    reports_dir.mkdir(parents=True, exist_ok=True)

    meta = dict(meta or {})
    meta.setdefault("domain", domain)
    meta.setdefault("timestamp", datetime.now().isoformat(timespec="seconds"))

    nmap_data = recon_data.get("nmap", {}) or {}
    counts = {
        "subdomains": len(sub_data.get("all", [])),
        "live_hosts": len(val_data.get("live_hosts", [])),
        "open_ports": nmap_data.get("open_ports_total", 0),
        "nuclei": recon_data.get("counts", {}).get("total", 0),
        "endpoints": len(js_data.get("endpoints", [])),
        "js_collected": collect_data.get("counts", {}).get("downloaded", 0),
        "secrets": (secrets_data.get("counts", {}).get("secrets", 0)
                    + secrets_data.get("counts", {}).get("trufflehog", 0)),
        "cloud": cloud_data.get("total", 0),
        "emails": len(email_data.get("emails", [])),
        "exposures": exposure_data.get("total", 0),
    }

    sections = [
        f"# AgentE Findings — {domain}\n",
        f"_Generated {meta['timestamp']}. Stages: {meta.get('stages', 'n/a')}._\n",
        "> Authorized reconnaissance output. See `LLM_PROMPT.md` for an LLM "
        "analysis hand-off, and `reports/index.html` for the interactive dashboard.\n",
        _sec_summary(meta, counts),
        _sec_nmap(nmap_data),
        _sec_nuclei(recon_data),
        _sec_live_hosts(val_data),
        _sec_subdomains(sub_data),
        _sec_endpoints(js_data),
        _sec_secrets(secrets_data),
        _sec_cloud(cloud_data),
        _sec_emails(email_data),
        _sec_exposure(exposure_data),
        _sec_ip(ip_data),
    ]
    findings_md = "\n\n".join(s for s in sections if s)
    findings_path = reports_dir / "findings.md"
    findings_path.write_text(findings_md, encoding="utf-8")

    # Collect every tool result for the prompt's "tools executed" list.
    all_tool_results = (
        sub_data.get("tool_results", []) + val_data.get("tool_results", [])
        + recon_data.get("tool_results", []) + js_data.get("tool_results", [])
        + collect_data.get("tool_results", []) + jsa_data.get("tool_results", [])
        + cloud_data.get("tool_results", []) + email_data.get("tool_results", [])
        + exposure_data.get("tool_results", []) + ip_data.get("tool_results", [])
        + secrets_data.get("tool_results", [])
    )
    prompt_md = _build_llm_prompt(meta, run_dir, all_tool_results)
    (reports_dir / "LLM_PROMPT.md").write_text(prompt_md, encoding="utf-8")

    log.info("Markdown reports -> %s , %s",
             findings_path, reports_dir / "LLM_PROMPT.md")
    return findings_path
