"""
Stage 3 — Screenshots & Vulnerability Scanning (gowitness + nuclei)

Runs immediately after validation (Stage 2), against the live URLs it produced.

  * gowitness  — screenshots every live URL and stores results in a local DB:
        gowitness scan file -f live-urls.txt --write-db
    Afterwards a report server is launched so the screenshots can be browsed:
        gowitness report server --host 0.0.0.0
    The server is a long-lived process: it is started *detached* and is never
    killed — it keeps serving while the rest of the pipeline runs and after it
    finishes.

  * nuclei     — template-based vulnerability scan of the same URLs:
        nuclei -l live-urls.txt -o nuclei-results.out
    Findings are parsed and grouped by host into a standalone HTML report.

Both scans can run for a long time and are executed with NO timeout (unless one
is set in config) so they are never killed before completing.
"""
import asyncio
import logging
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse

from modules.port_scan import run_nmap_scan
from utils.htmlreport import esc, page
from utils.runner import ToolResult, run_parallel, run_tool, spawn_detached

log = logging.getLogger("agente.recon_scan")

# nuclei -o line format (no colour when written to a file):
#   [template-id] [protocol] [severity] matched-url [extractor,info]
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_NUCLEI_RE = re.compile(
    r"^\[(?P<tid>[^\]]+)\]\s+"
    r"\[(?P<proto>[^\]]+)\]\s+"
    r"\[(?P<sev>[^\]]+)\]\s+"
    r"(?P<url>\S+)"
    r"(?:\s+\[(?P<extra>.*)\])?\s*$"
)

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _host_of(url: str) -> str:
    try:
        netloc = urlparse(url).netloc
        return netloc or url
    except Exception:
        return url


def _host_noport(url: str) -> str:
    """Host of a URL, lowercased and without any port — for FQDN matching."""
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return url.lower()


# ──────────────────────────────────────────────────────────────────────────────
# Tool invocations
# ──────────────────────────────────────────────────────────────────────────────

async def run_gowitness_scan(stage_dir: Path, cfg: dict) -> ToolResult:
    """Screenshot every live URL and write results to gowitness' local DB."""
    cmd = [
        "gowitness", "scan", "file",
        "-f", "live-urls.txt",
        "--write-db",
        *cfg.get("extra_args", []),
    ]
    # cwd = stage_dir so screenshots/ and gowitness.sqlite3 land there and the
    # report server (same cwd) can find them.
    return await run_tool(cmd, "gowitness", cwd=stage_dir, timeout=cfg.get("timeout"))


async def run_nuclei(stage_dir: Path, cfg: dict,
                     input_name: str = "live-urls.txt") -> ToolResult:
    """Template-based vulnerability scan of the given URL list (relative to cwd)."""
    cmd = [
        "nuclei",
        "-l", input_name,
        "-o", "nuclei-results.out",
        *cfg.get("extra_args", []),
    ]
    return await run_tool(cmd, "nuclei", cwd=stage_dir, timeout=cfg.get("timeout"))


def _start_report_server(stage_dir: Path, cfg: dict) -> dict:
    """Launch `gowitness report server` detached (never awaited, never killed)."""
    host = str(cfg.get("report_host", "0.0.0.0"))
    port = cfg.get("report_port")
    cmd = ["gowitness", "report", "server", "--host", host]
    if port:
        cmd += ["--port", str(port)]
    info = spawn_detached(
        cmd, "gowitness-server", cwd=stage_dir,
        log_file=stage_dir / "gowitness_server.log",
    )
    # gowitness' default listen port is 7171.
    info["url"] = f"http://{host}:{port or 7171}"
    return info


# ──────────────────────────────────────────────────────────────────────────────
# nuclei output parsing
# ──────────────────────────────────────────────────────────────────────────────

def _parse_nuclei(out_file: Path) -> list[dict]:
    findings: list[dict] = []
    if not out_file.exists():
        return findings
    for raw in out_file.read_text(errors="replace").splitlines():
        line = _ANSI_RE.sub("", raw).strip()
        if not line:
            continue
        m = _NUCLEI_RE.match(line)
        if not m:
            continue
        sev = (m.group("sev") or "unknown").lower()
        url = m.group("url")
        findings.append({
            "template": m.group("tid"),
            "protocol": m.group("proto"),
            "severity": sev,
            "sev_weight": _SEV_ORDER.get(sev, 5),
            "url": url,
            "host": _host_of(url),
            "extra": (m.group("extra") or "").strip(),
        })
    findings.sort(key=lambda f: (f["sev_weight"], f["host"]))
    return findings


def _count_screenshots(stage_dir: Path) -> int:
    shots = stage_dir / "screenshots"
    if not shots.exists():
        return 0
    return sum(1 for p in shots.rglob("*") if p.is_file())


# ──────────────────────────────────────────────────────────────────────────────
# HTML report (findings grouped by host)
# ──────────────────────────────────────────────────────────────────────────────

def _sev_badge(sev: str) -> str:
    return f'<span class="sev-{esc(sev)}">{esc(sev.upper())}</span>'


def _finding_row(f: dict, include_host: bool = True) -> str:
    host_cell = f'<td>{esc(f["host"])}</td>' if include_host else ""
    extra = (f'<span class="match-tag">{esc(f["extra"][:120])}</span>'
             if f["extra"] else "")
    return (
        f'<tr data-order="{f["sev_weight"]}">'
        f'<td class="sev-{esc(f["severity"])}" data-order="{f["sev_weight"]}">'
        f'{esc(f["severity"].upper())}</td>'
        f'{host_cell}'
        f'<td class="small">{esc(f["template"])}</td>'
        f'<td class="small text-muted">{esc(f["protocol"])}</td>'
        f'<td class="small"><a href="{esc(f["url"])}" target="_blank">{esc(f["url"])}</a></td>'
        f'<td>{extra}</td>'
        f'</tr>'
    )


def _build_nmap_section(nmap_data: dict) -> str:
    """Render the Nmap port-scan results as an HTML section for the Stage 3 page."""
    if not nmap_data or not nmap_data.get("enabled", False):
        return ""
    if nmap_data.get("skipped") and not nmap_data.get("hosts"):
        reason = esc(nmap_data.get("skip_reason", "not run"))
        return (
            '<div class="section-card p-3 mb-4">'
            '<div class="section-title">Nmap Port Scan (--ip-list scope)</div>'
            f'<p class="text-muted small mb-0">Port scan not run: {reason}.</p></div>'
        )

    hosts = nmap_data.get("hosts", [])
    rows = []
    for h in hosts:
        ip = esc(h.get("ip", ""))
        hostname = esc(h.get("hostname", ""))
        host_label = f"{ip} <span class='text-muted small'>({hostname})</span>" if hostname else ip
        ports = h.get("ports", [])
        if not ports:
            rows.append(f'<tr><td>{host_label}</td><td colspan="4" '
                        f'class="text-muted small">no open ports</td></tr>')
            continue
        for i, p in enumerate(ports):
            svc = esc(p.get("service", ""))
            product = " ".join(x for x in (p.get("product", ""), p.get("version", ""),
                                           p.get("extrainfo", "")) if x)
            scripts = p.get("scripts", {}) or {}
            script_txt = "; ".join(f"{esc(k)}: {esc(v[:160])}" for k, v in scripts.items())
            first_cell = host_label if i == 0 else ""
            rows.append(
                f'<tr><td>{first_cell}</td>'
                f'<td class="small"><strong>{esc(str(p.get("port","")))}/{esc(p.get("proto",""))}</strong></td>'
                f'<td class="small">{svc}</td>'
                f'<td class="small text-muted">{esc(product)}</td>'
                f'<td class="small text-muted">{script_txt}</td></tr>'
            )
    table = ('<table class="table table-sm w-100">'
             '<thead><tr><th>Host</th><th>Port</th><th>Service</th>'
             '<th>Product / Version</th><th>Scripts</th></tr></thead>'
             f'<tbody>{"".join(rows)}</tbody></table>')
    note = (f'{nmap_data.get("open_ports_total", 0)} open port(s) across '
            f'{len([h for h in hosts if h.get("ports")])} host(s); '
            f'{nmap_data.get("hosts_scanned", 0)} target(s) scanned. '
            'Scope: hosts supplied via <code>--ip-list</code>. '
            'Raw output: <code>03-screenshots/nmap_*.xml</code> / <code>.txt</code>.')
    return (
        '<div class="section-card p-3 mb-4">'
        '<div class="section-title">Nmap Port Scan (--ip-list scope)</div>'
        f'<p class="text-muted small">{note}</p>{table}</div>'
    )


def _build_nuclei_report(target: str, findings: list[dict], by_host: dict,
                         sev_counts: Counter, screenshots: int,
                         server: dict, report_path: Path,
                         nmap_data: dict | None = None) -> None:
    total = len(findings)
    hosts = len(by_host)

    def card(value, label, cls="") -> str:
        return (f'<div class="col-6 col-md">'
                f'<div class="stat-card p-3 text-center">'
                f'<div class="stat-value {cls}">{value}</div>'
                f'<div class="stat-label">{label}</div></div></div>')

    open_ports = (nmap_data or {}).get("open_ports_total", 0)
    cards = "".join([
        card(total, "Findings"),
        card(sev_counts.get("critical", 0), "Critical &#9888;", "sev-critical"),
        card(sev_counts.get("high", 0), "High", "sev-high"),
        card(sev_counts.get("medium", 0), "Medium", "sev-medium"),
        card(sev_counts.get("low", 0), "Low", "sev-low"),
        card(sev_counts.get("info", 0), "Info", "sev-info"),
        card(hosts, "Hosts"),
        card(screenshots, "Screenshots"),
        card(open_ports, "Open Ports"),
    ])

    nmap_section = _build_nmap_section(nmap_data or {})

    if server.get("started"):
        server_note = (
            f'<p class="text-muted small mb-3">gowitness screenshot server is running at '
            f'<a href="{esc(server.get("url",""))}" target="_blank">{esc(server.get("url",""))}</a> '
            f'(pid {esc(server.get("pid",""))}) — it was left running so the screenshots stay '
            f'browsable.</p>'
        )
    else:
        server_note = (
            f'<p class="text-muted small mb-3">gowitness report server was not started: '
            f'{esc(server.get("reason","n/a"))}.</p>'
        )

    all_rows = "\n".join(_finding_row(f, include_host=True) for f in findings)

    # Per-host panes
    host_tabs, host_panes, dt_ids = [], [], ["#tblAll"]
    for idx, host in enumerate(sorted(by_host)):
        items = sorted(by_host[host], key=lambda x: x["sev_weight"])
        crit_high = sum(1 for f in items if f["severity"] in ("critical", "high"))
        badge = (f' <span class="badge sev-high">{crit_high}&#9888;</span>'
                 if crit_high else "")
        tbl_id = f"tblHost{idx}"
        dt_ids.append(f"#{tbl_id}")
        host_tabs.append(
            f'<li class="nav-item"><button class="nav-link" data-bs-toggle="pill" '
            f'data-bs-target="#host-{idx}">{esc(host)} '
            f'<span class="badge bg-secondary">{len(items)}</span></button></li>'
        )
        rows = "\n".join(_finding_row(f, include_host=False) for f in items)
        host_panes.append(
            f'<div class="tab-pane fade" id="host-{idx}">'
            f'<div class="section-card p-3">'
            f'<div class="section-title">{esc(host)} &mdash; {len(items)} finding(s){badge}</div>'
            f'<table id="{tbl_id}" class="table table-sm w-100">'
            f'<thead><tr><th>Severity</th><th>Template</th><th>Proto</th>'
            f'<th>URL</th><th>Extracted</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div></div>'
        )

    body = f"""
<div class="row g-3 mb-4">{cards}</div>
{server_note}
{nmap_section}

<ul class="nav nav-pills mb-3 flex-wrap">
  <li class="nav-item"><button class="nav-link active" data-bs-toggle="pill" data-bs-target="#tab-all">All Findings</button></li>
  {"".join(host_tabs)}
</ul>

<div class="tab-content">
  <div class="tab-pane fade show active" id="tab-all">
    <div class="section-card p-3">
      <div class="section-title">All Nuclei Findings ({total})</div>
      <table id="tblAll" class="table table-sm w-100">
        <thead><tr><th>Severity</th><th>Host</th><th>Template</th><th>Proto</th>
                   <th>URL</th><th>Extracted</th></tr></thead>
        <tbody>{all_rows}</tbody>
      </table>
    </div>
  </div>
  {"".join(host_panes)}
</div>
"""
    # Per-host tables live inside inactive tabs, so init them all explicitly.
    dt_init = "\n".join(
        f"  if ($('{tid}').length) $('{tid}').DataTable(dtOpts);" for tid in dt_ids
    )
    html = page(target=target, active="03-nuclei.html",
                subtitle="Nuclei Vulnerability Scan", body=body,
                extra_script=dt_init)
    report_path.write_text(html, encoding="utf-8")
    log.info("Nuclei report -> %s", report_path)


def _empty(report_file: str = "", skip_reason: str = "",
           nmap_data: dict | None = None) -> dict:
    nmap_data = nmap_data or {"enabled": False, "hosts": [], "open_ports_total": 0}
    return {
        "findings": [], "by_host": {},
        "counts": {"total": 0, "critical": 0, "high": 0, "medium": 0,
                   "low": 0, "info": 0, "hosts": 0},
        "screenshots": 0, "server": {"started": False, "reason": skip_reason},
        "nmap": nmap_data,
        "report_file": report_file, "skipped": True, "skip_reason": skip_reason,
        "tool_results": list(nmap_data.get("tool_results", [])),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Stage entry point
# ──────────────────────────────────────────────────────────────────────────────

async def run_recon(domain: str, live_urls_file: Path, stage_dir: Path,
                    reports_dir: Path, cfg: dict,
                    nuclei_fqdns: set[str] | None = None,
                    nmap_targets: list[str] | None = None) -> dict:
    """
    Run Nmap (in-scope --ip-list hosts) + gowitness + nuclei.

    nuclei_fqdns: when None (default), nuclei scans the full live-URL list, like
    every other tool. When a set is supplied (via --nuclei-ip-list-only), nuclei
    is scoped to only the live URLs whose host is one of those --ip-list-derived
    targets — the FCrDNS-validated FQDNs and/or the raw IPs that had no resolvable
    domain name; those targets are written to a separate ``ip-list-live-urls.txt``.
    gowitness still screenshots the full list.

    nmap_targets: IPs from ``--ip-list`` to port-scan. Nmap runs *before* nuclei
    and only against these in-scope targets; when None/empty the port scan is
    skipped. Nmap output feeds the same Stage 3 report.
    """
    log.info("=== Stage 3: Port Scan + Screenshots + Vulnerability Scanning "
             "(nmap + gowitness + nuclei) ===")
    recon_cfg = cfg.get("recon", {})
    nmap_cfg = recon_cfg.get("nmap", {})
    report_path = reports_dir / "03-nuclei.html"

    stage_dir.mkdir(parents=True, exist_ok=True)

    # ── Nmap port scan (in-scope --ip-list targets) — runs BEFORE nuclei ──
    nmap_data = {"enabled": False, "hosts": [], "open_ports_total": 0,
                 "tool_results": []}
    if nmap_targets and nmap_cfg.get("enabled", True):
        nmap_data = await run_nmap_scan(nmap_targets, stage_dir, nmap_cfg)
    elif nmap_targets:
        log.info("Recon: nmap disabled in config — skipping port scan")

    # Materialise the exact input file the tool commands expect (live-urls.txt).
    live_urls: list[str] = []
    if live_urls_file and Path(live_urls_file).exists():
        live_urls = [u.strip() for u in Path(live_urls_file).read_text(
            errors="replace").splitlines() if u.strip()]
    (stage_dir / "live-urls.txt").write_text("\n".join(live_urls), encoding="utf-8")

    if not live_urls:
        log.warning("Recon: no live URLs — skipping gowitness/nuclei"
                    + (" (nmap results retained)" if nmap_data.get("hosts") else ""))
        _build_nuclei_report(domain, [], {}, Counter(), 0,
                             {"started": False, "reason": "no live URLs"}, report_path,
                             nmap_data=nmap_data)
        data = _empty(str(report_path), "no live URLs", nmap_data=nmap_data)
        return data

    # Decide what nuclei scans. gowitness always uses the full live-urls.txt.
    nuclei_input = "live-urls.txt"
    nuclei_targets = live_urls
    if nuclei_fqdns is not None:
        nuclei_targets = [u for u in live_urls if _host_noport(u) in nuclei_fqdns]
        nuclei_input = "ip-list-live-urls.txt"
        (stage_dir / nuclei_input).write_text("\n".join(nuclei_targets), encoding="utf-8")
        log.info("Recon: nuclei scoped to --ip-list targets — %d of %d live URL(s)",
                 len(nuclei_targets), len(live_urls))

    async def _nuclei_or_skip() -> ToolResult:
        if not nuclei_targets:
            log.warning("Recon: no nuclei targets after --ip-list filtering — skipping nuclei")
            return ToolResult(
                tool="nuclei", cmd=[], returncode=0, stdout="", stderr="",
                duration=0.0, skipped=True,
                skip_reason="no live URLs matched --ip-list targets",
            )
        return await run_nuclei(stage_dir, recon_cfg.get("nuclei", {}),
                                input_name=nuclei_input)

    # gowitness scan and nuclei are independent — run them together. Neither is
    # killed early (no timeout unless configured).
    gw_result, nuclei_result = await run_parallel(
        run_gowitness_scan(stage_dir, recon_cfg.get("gowitness", {})),
        _nuclei_or_skip(),
        max_concurrency=2,
    )

    # After screenshots + probing, bring up the browsable report server.
    server = {"started": False, "reason": "gowitness scan skipped"}
    if not gw_result.skipped and recon_cfg.get("gowitness", {}).get("report_server", True):
        server = _start_report_server(stage_dir, recon_cfg.get("gowitness", {}))

    findings = _parse_nuclei(stage_dir / "nuclei-results.out")
    by_host: dict[str, list] = defaultdict(list)
    for f in findings:
        by_host[f["host"]].append(f)
    sev_counts = Counter(f["severity"] for f in findings)
    screenshots = _count_screenshots(stage_dir)

    _build_nuclei_report(domain, findings, by_host, sev_counts,
                         screenshots, server, report_path, nmap_data=nmap_data)

    counts = {
        "total": len(findings),
        "critical": sev_counts.get("critical", 0),
        "high": sev_counts.get("high", 0),
        "medium": sev_counts.get("medium", 0),
        "low": sev_counts.get("low", 0),
        "info": sev_counts.get("info", 0),
        "hosts": len(by_host),
    }
    log.info("Recon: nuclei findings=%d (crit=%d high=%d med=%d) across %d host(s); "
             "screenshots=%d; server=%s",
             counts["total"], counts["critical"], counts["high"], counts["medium"],
             counts["hosts"], screenshots,
             server.get("url") if server.get("started") else "not started")

    return {
        "findings": findings,
        "by_host": {h: v for h, v in by_host.items()},
        "counts": counts,
        "screenshots": screenshots,
        "server": server,
        "nmap": nmap_data,
        "report_file": str(report_path),
        "skipped": False,
        "skip_reason": "",
        "tool_results": [
            {"tool": r.tool, "duration": r.duration, "skipped": r.skipped,
             "skip_reason": r.skip_reason}
            for r in (gw_result, nuclei_result)
        ] + list(nmap_data.get("tool_results", [])),
    }
