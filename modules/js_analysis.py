"""
Stage 5 — Client-Side JavaScript Analysis (semgrep + DOM heuristics)

Runs immediately after Stage 4 (download + Prettier beautification). For every
directory under ``collected/`` that holds ``*.js`` files, semgrep is executed
against those files with a fixed set of rule packs, and a regex-based DOM
heuristic scan flags sources / sinks / postMessage / event listeners. All
findings are aggregated, a standalone ``semgrep_report.html`` is written
(grouped per asset), and a summary is folded into the main AgentE report.

semgrep is optional: if it is not on PATH the DOM heuristics still run (they are
pure Python), and the stage degrades gracefully rather than failing.

Adapted from the standalone semgrep_scan.py utility.
"""
import asyncio
import glob
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

log = logging.getLogger("agente.js_analysis")

# Rule packs passed to semgrep, in order, via repeated --config flags.
CONFIGS = [
    "p/owasp-top-ten",
    "p/secrets",
    "p/javascript",
    "p/security-audit",
    "p/default",
    "p/cwe-top-25",
    "p/r2c-security-audit",
    "p/xss",
]

EXCLUDE_DIRS = {"node_modules"}

# semgrep severity -> (display label, css class, sort weight)
SEVERITY_MAP = {
    "ERROR":   ("High",   "sev-high",   0),
    "WARNING": ("Medium", "sev-medium", 1),
    "INFO":    ("Low",    "sev-low",    2),
}

# ──────────────────────────────────────────────────────────────────────────────
# DOM taint heuristics — sources, sinks, postMessage and event listeners.
# Regex-based hints (not a real taint engine) to point a reviewer at hot lines.
# ──────────────────────────────────────────────────────────────────────────────
_DOM_PATTERNS_RAW = [
    # ── DOM sources (attacker-controllable input) ──
    ("location.href/search/hash/…", "Source", "dom-source",
     r"\blocation\s*\.\s*(href|search|hash|pathname|host|hostname|protocol|origin)\b"),
    ("document.URL/referrer/cookie/…", "Source", "dom-source",
     r"\bdocument\s*\.\s*(URL|documentURI|baseURI|referrer|cookie)\b"),
    ("window.name", "Source", "dom-source", r"\bwindow\s*\.\s*name\b"),
    ("document.location", "Source", "dom-source", r"\bdocument\s*\.\s*location\b"),
    ("local/sessionStorage.getItem", "Source", "dom-source",
     r"\b(localStorage|sessionStorage)\s*\.\s*getItem\s*\("),
    ("URLSearchParams / .get()", "Source", "dom-source",
     r"\bnew\s+URLSearchParams\b|\bsearchParams\s*\.\s*get\s*\("),
    ("history.pushState/replaceState", "Source", "dom-source",
     r"\bhistory\s*\.\s*(pushState|replaceState)\s*\("),

    # ── DOM sinks (dangerous assignment / execution) ──
    ("innerHTML / outerHTML", "Sink", "dom-sink",
     r"\.\s*(innerHTML|outerHTML)\s*="),
    ("insertAdjacentHTML", "Sink", "dom-sink", r"\.\s*insertAdjacentHTML\s*\("),
    ("document.write(ln)", "Sink", "dom-sink", r"\bdocument\s*\.\s*write(ln)?\s*\("),
    ("eval", "Sink", "dom-sink", r"\beval\s*\("),
    ("Function constructor", "Sink", "dom-sink", r"\b(new\s+)?Function\s*\("),
    ("setTimeout / setInterval", "Sink", "dom-sink",
     r"\bset(Timeout|Interval)\s*\("),
    ("element.src / .href assignment", "Sink", "dom-sink",
     r"\.\s*(src|href)\s*=\s*"),
    ("setAttribute(src|href|on*)", "Sink", "dom-sink",
     r"\.\s*setAttribute\s*\(\s*['\"](src|href|on\w+)['\"]"),
    ("location.assign/replace", "Sink", "dom-sink",
     r"\blocation\s*\.\s*(assign|replace)\s*\("),
    ("window.open", "Sink", "dom-sink", r"\bwindow\s*\.\s*open\s*\("),
    ("jQuery .html()/.append()", "Sink", "dom-sink",
     r"\.\s*(html|append|prepend|after|before|wrap)\s*\("),
    ("document.domain assignment", "Sink", "dom-sink",
     r"\bdocument\s*\.\s*domain\s*="),

    # ── postMessage / cross-origin messaging ──
    ("postMessage() call", "postMessage", "dom-msg", r"\.\s*postMessage\s*\("),
    ("message event listener", "postMessage", "dom-msg",
     r"\baddEventListener\s*\(\s*['\"]message['\"]"),
    ("onmessage handler", "postMessage", "dom-msg", r"\bonmessage\s*="),

    # ── generic event listeners (excluding 'message', handled above) ──
    ("addEventListener", "Listener", "dom-listener",
     r"\baddEventListener\s*\(\s*['\"](?!message['\"])"),
]

DOM_PATTERNS = [(name, cat, css, re.compile(rx))
                for name, cat, css, rx in _DOM_PATTERNS_RAW]

DOM_CAT_WEIGHT = {"Sink": 0, "Source": 1, "postMessage": 2, "Listener": 3}


# ──────────────────────────────────────────────────────────────────────────────
# Filesystem walking
# ──────────────────────────────────────────────────────────────────────────────

def find_js_dirs(root):
    """Yield directories under *root* that directly contain *.js files."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        if any(name.endswith(".js") for name in filenames):
            yield dirpath


def js_files_in(directory):
    """Absolute paths of *.js files directly in *directory* (globbed in Python
    so paths with spaces survive)."""
    return sorted(glob.glob(os.path.join(directory, "*.js")))


def asset_for(path, root):
    """Map a finding's file path to its asset (top-level dir under root)."""
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return path
    parts = rel.split(os.sep)
    if len(parts) > 1 and parts[0] not in ("", "."):
        return parts[0]
    return os.path.basename(os.path.abspath(root)) or "(root)"


# ──────────────────────────────────────────────────────────────────────────────
# DOM heuristic scan
# ──────────────────────────────────────────────────────────────────────────────

def scan_dom_patterns(file_path, root, max_per_file=1000):
    """Scan one .js file for DOM sources/sinks, postMessage and listeners."""
    try:
        with open(file_path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        log.warning("JS analysis: could not read %s: %s", file_path, exc)
        return []

    asset = asset_for(file_path, root)
    findings = []
    for name, category, css, rx in DOM_PATTERNS:
        for m in rx.finditer(text):
            pos = m.start()
            line = text.count("\n", 0, pos) + 1
            ctx = text[max(0, pos - 40):m.end() + 60]
            ctx = re.sub(r"\s+", " ", ctx).strip()
            findings.append({
                "asset": asset,
                "path": file_path,
                "line": line,
                "category": category,
                "cat_weight": DOM_CAT_WEIGHT.get(category, 9),
                "css": css,
                "name": name,
                "match": m.group(0).strip(),
                "snippet": ctx,
            })
            if len(findings) >= max_per_file:
                log.info("JS analysis: DOM scan capped at %d hits for %s",
                         max_per_file, file_path)
                return findings
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# semgrep execution
# ──────────────────────────────────────────────────────────────────────────────

def _build_command(semgrep_bin, directory, configs):
    cmd = [semgrep_bin]
    for config in configs:
        cmd.extend(["--config", config])
    cmd.extend(["--exclude", "node_modules", "--json"])
    cmd.extend(js_files_in(directory))
    return cmd


def run_for_directory(semgrep_bin, directory, configs, raw_dir, timeout):
    """Run semgrep for one directory. Returns (return_code, results_list)."""
    targets = js_files_in(directory)
    if not targets:
        return 0, []

    cmd = _build_command(semgrep_bin, directory, configs)
    log.info("JS analysis: scanning %s (%d file(s))", directory, len(targets))
    try:
        result = subprocess.run(
            cmd, shell=False, capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        log.error("JS analysis: semgrep not found at run time")
        return 127, []
    except subprocess.TimeoutExpired:
        log.warning("JS analysis: semgrep timed out in %s", directory)
        return 124, []

    results = []
    if result.stdout:
        try:
            results = json.loads(result.stdout).get("results", [])
        except json.JSONDecodeError:
            log.warning("JS analysis: could not parse semgrep JSON for %s", directory)

    if raw_dir is not None:
        raw_dir.mkdir(parents=True, exist_ok=True)
        safe = directory.replace(os.sep, "_").replace(":", "")
        (raw_dir / f"semgrep_{safe}.json").write_text(
            result.stdout or "{}", encoding="utf-8")

    log.info("JS analysis: %d semgrep finding(s) in %s", len(results), directory)
    return result.returncode, results


def _normalize(finding, root):
    """Flatten a raw semgrep result into the fields the report needs."""
    extra = finding.get("extra", {}) or {}
    meta = extra.get("metadata", {}) or {}
    sev_raw = (extra.get("severity") or "INFO").upper()
    label, css, weight = SEVERITY_MAP.get(sev_raw, ("Low", "sev-low", 2))

    def _flat(val):
        if isinstance(val, list):
            return ", ".join(str(v) for v in val)
        return str(val) if val else ""

    return {
        "asset": asset_for(finding.get("path", ""), root),
        "path": finding.get("path", ""),
        "line": (finding.get("start", {}) or {}).get("line", ""),
        "check_id": finding.get("check_id", ""),
        "severity": label,
        "sev_css": css,
        "sev_weight": weight,
        "message": (extra.get("message") or "").strip(),
        "owasp": _flat(meta.get("owasp")),
        "cwe": _flat(meta.get("cwe")),
        "snippet": (extra.get("lines") or "").strip(),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Standalone HTML report
# ──────────────────────────────────────────────────────────────────────────────

def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentE — Semgrep Findings</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.datatables.net/2.0.7/css/dataTables.bootstrap5.min.css">
<style>
:root {{
  --accent: #00ff88; --accent2: #0dcaf0;
  --bg-card: #0f1117; --bg-page: #080b10; --border: #1e2940;
}}
body {{ background: var(--bg-page); font-family: 'Segoe UI', system-ui, sans-serif; }}
.navbar-brand {{ color: var(--accent) !important; font-weight: 700; letter-spacing: 2px; }}
.stat-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
              transition: transform .2s; }}
.stat-card:hover {{ transform: translateY(-3px); }}
.stat-value {{ font-size: 2.4rem; font-weight: 700; color: var(--accent); }}
.stat-label {{ color: #8899aa; font-size: .85rem; text-transform: uppercase; letter-spacing: 1px; }}
.section-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; }}
.section-title {{ color: var(--accent2); font-weight: 600; border-bottom: 1px solid var(--border);
                  padding-bottom: .5rem; margin-bottom: 1rem; }}
.nav-pills .nav-link.active {{ background: var(--accent); color: #000 !important; font-weight: 600; }}
.nav-pills .nav-link {{ color: #aaa; }}
table.dataTable {{ background: var(--bg-card) !important; }}
table.dataTable thead th {{ background: #0a0d14 !important; color: var(--accent2) !important;
                             border-bottom: 2px solid var(--border) !important; }}
table.dataTable tbody tr {{ background: var(--bg-card) !important; color: #cdd9e5; }}
table.dataTable tbody tr:hover {{ background: #131822 !important; }}
.dataTables_wrapper .dataTables_filter input,
.dataTables_wrapper .dataTables_length select {{
  background: #131822 !important; color: #cdd9e5 !important;
  border: 1px solid var(--border) !important; border-radius: 6px; }}
.dataTables_wrapper .dataTables_info,
.dataTables_wrapper .dataTables_paginate .paginate_button {{ color: #8899aa !important; }}
.dataTables_wrapper .dataTables_paginate .paginate_button.current {{
  background: var(--accent) !important; color: #000 !important;
  border-radius: 4px; border: none !important; }}
.sev-high {{ color: #ff4d4d; font-weight: 700; }}
.sev-medium {{ color: #ffc107; font-weight: 600; }}
.sev-low {{ color: #0dcaf0; }}
.dom-sink {{ color: #ff6b6b; font-weight: 700; }}
.dom-source {{ color: #0dcaf0; font-weight: 600; }}
.dom-msg {{ color: #c77dff; font-weight: 600; }}
.dom-listener {{ color: #8899aa; }}
.match-tag {{ font-family: monospace; font-size: .74rem; color: #ffd166;
             background: #1a1500; padding: 2px 6px; border-radius: 4px; }}
.code-snippet {{ font-family: monospace; font-size: .75rem; color: #cdd9e5;
                 background: #131822; padding: 4px 8px; border-radius: 4px;
                 border-left: 3px solid var(--accent2); white-space: pre-wrap;
                 max-width: 480px; display: inline-block; }}
.check-id {{ font-family: monospace; font-size: .72rem; color: #8899aa; }}
.chart-container {{ position: relative; height: 260px; }}
.ts {{ color: #556; font-size: .78rem; }}
</style>
</head>
<body>

<nav class="navbar navbar-dark px-4 py-3" style="background:#080b10; border-bottom:1px solid var(--border);">
  <span class="navbar-brand">&#9670; AgentE &mdash; Semgrep</span>
  <span class="text-muted small">Root: <strong class="text-info">{root}</strong>
    &nbsp;|&nbsp; Generated: <span class="ts">{generated}</span></span>
</nav>

<div class="container-fluid py-4 px-4">

<div class="row g-3 mb-4">
  <div class="col-6 col-md">
    <div class="stat-card p-3 text-center">
      <div class="stat-value">{total_findings}</div>
      <div class="stat-label">Semgrep Findings</div>
    </div>
  </div>
  <div class="col-6 col-md">
    <div class="stat-card p-3 text-center">
      <div class="stat-value">{total_assets}</div>
      <div class="stat-label">Assets Scanned</div>
    </div>
  </div>
  <div class="col-6 col-md">
    <div class="stat-card p-3 text-center">
      <div class="stat-value sev-high">{total_high}</div>
      <div class="stat-label">High &#9888;</div>
    </div>
  </div>
  <div class="col-6 col-md">
    <div class="stat-card p-3 text-center">
      <div class="stat-value sev-medium">{total_medium}</div>
      <div class="stat-label">Medium</div>
    </div>
  </div>
  <div class="col-6 col-md">
    <div class="stat-card p-3 text-center">
      <div class="stat-value dom-sink">{total_sinks}</div>
      <div class="stat-label">DOM Sinks</div>
    </div>
  </div>
  <div class="col-6 col-md">
    <div class="stat-card p-3 text-center">
      <div class="stat-value dom-msg">{total_postmessage}</div>
      <div class="stat-label">postMessage</div>
    </div>
  </div>
</div>

<div class="row g-3 mb-4">
  <div class="col-md-4">
    <div class="section-card p-3">
      <div class="section-title">Severity Distribution</div>
      <div class="chart-container"><canvas id="chartSeverity"></canvas></div>
    </div>
  </div>
  <div class="col-md-8">
    <div class="section-card p-3">
      <div class="section-title">Findings per Asset</div>
      <div class="chart-container"><canvas id="chartAssets"></canvas></div>
    </div>
  </div>
</div>

<ul class="nav nav-pills mb-3 flex-wrap" id="mainTabs">
  <li class="nav-item"><button class="nav-link active" data-bs-toggle="pill" data-bs-target="#tab-all">All Findings</button></li>
  {dom_tab_button}
  {asset_tab_buttons}
</ul>

<div class="tab-content">

<div class="tab-pane fade show active" id="tab-all">
  <div class="section-card p-3">
    <div class="section-title">All Semgrep Findings ({total_findings})</div>
    <table id="tblAll" class="table table-sm w-100">
      <thead><tr><th>Severity</th><th>Asset</th><th>File</th><th>Line</th>
                 <th>Rule</th><th>Message</th><th>OWASP / CWE</th><th>Code</th></tr></thead>
      <tbody>{rows_all}</tbody>
    </table>
  </div>
</div>

{dom_pane}

{asset_panes}

</div><!-- end tab-content -->
</div><!-- end container -->

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/2.0.7/js/dataTables.min.js"></script>
<script src="https://cdn.datatables.net/2.0.7/js/dataTables.bootstrap5.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<script>
$(function() {{
  const dtOpts = {{ pageLength: 25, lengthMenu: [25, 50, 100, 500], order: [[0, 'asc']] }};
  {datatable_ids}.forEach(id => {{ if ($(id).length) $(id).DataTable(dtOpts); }});

  const sevData = {chart_severity_json};
  new Chart(document.getElementById('chartSeverity'), {{
    type: 'doughnut',
    data: {{ labels: sevData.labels,
      datasets: [{{ data: sevData.values,
        backgroundColor: ['#ff4d4d', '#ffc107', '#0dcaf0'], borderWidth: 0 }}] }},
    options: {{ plugins: {{ legend: {{ labels: {{ color: '#cdd9e5' }} }} }}, cutout: '65%' }}
  }});

  const assetData = {chart_assets_json};
  new Chart(document.getElementById('chartAssets'), {{
    type: 'bar',
    data: {{ labels: assetData.labels,
      datasets: [{{ data: assetData.values, backgroundColor: '#00ff88', borderWidth: 0 }}] }},
    options: {{ indexAxis: 'y', plugins: {{ legend: {{ display: false }} }},
      scales: {{ x: {{ ticks: {{ color: '#8899aa' }}, grid: {{ color: '#1e2940' }} }},
                 y: {{ ticks: {{ color: '#8899aa' }}, grid: {{ color: '#1e2940' }} }} }} }}
  }});

  const domCanvas = document.getElementById('chartDom');
  if (domCanvas) {{
    const domData = {chart_dom_json};
    new Chart(domCanvas, {{
      type: 'doughnut',
      data: {{ labels: domData.labels,
        datasets: [{{ data: domData.values,
          backgroundColor: ['#ff6b6b', '#0dcaf0', '#c77dff', '#8899aa'],
          borderWidth: 0 }}] }},
      options: {{ plugins: {{ legend: {{ labels: {{ color: '#cdd9e5' }} }} }}, cutout: '60%' }}
    }});
  }}
}});
</script>
</body>
</html>
"""


def _finding_row(f, include_asset=True):
    owasp_cwe = " ".join(p for p in (
        f'<span class="badge bg-secondary">{_esc(f["owasp"])}</span>' if f["owasp"] else "",
        f'<span class="badge bg-dark border">{_esc(f["cwe"])}</span>' if f["cwe"] else "",
    ) if p)
    asset_cell = f'<td>{_esc(f["asset"])}</td>' if include_asset else ""
    snippet = _esc(f["snippet"][:300])
    return (
        f'<tr data-order="{f["sev_weight"]}">'
        f'<td class="{f["sev_css"]}" data-order="{f["sev_weight"]}">{f["severity"]}</td>'
        f'{asset_cell}'
        f'<td class="small text-muted">{_esc(f["path"])}</td>'
        f'<td>{_esc(f["line"])}</td>'
        f'<td class="check-id">{_esc(f["check_id"])}</td>'
        f'<td class="small">{_esc(f["message"])}</td>'
        f'<td>{owasp_cwe}</td>'
        f'<td><span class="code-snippet">{snippet}</span></td>'
        f'</tr>'
    )


def _dom_row(d):
    return (
        f'<tr data-order="{d["cat_weight"]}">'
        f'<td class="{d["css"]}" data-order="{d["cat_weight"]}">{d["category"]}</td>'
        f'<td>{_esc(d["asset"])}</td>'
        f'<td class="small text-muted">{_esc(d["path"])}</td>'
        f'<td>{_esc(d["line"])}</td>'
        f'<td class="small">{_esc(d["name"])}</td>'
        f'<td><span class="match-tag">{_esc(d["match"][:60])}</span></td>'
        f'<td><span class="code-snippet">{_esc(d["snippet"][:300])}</span></td>'
        f'</tr>'
    )


def _build_dom_section(dom_findings):
    if not dom_findings:
        return "", "", json.dumps({"labels": [], "values": []})

    cat_counts = Counter(d["category"] for d in dom_findings)
    rows = "\n".join(_dom_row(d) for d in sorted(
        dom_findings, key=lambda x: (x["cat_weight"], x["asset"])))

    tab_button = (
        '<li class="nav-item"><button class="nav-link" data-bs-toggle="pill" '
        f'data-bs-target="#tab-dom">DOM &amp; Messaging '
        f'<span class="badge bg-secondary">{len(dom_findings)}</span></button></li>'
    )

    pane = (
        '<div class="tab-pane fade" id="tab-dom">'
        '<div class="row g-3 mb-3">'
        '<div class="col-md-4"><div class="section-card p-3">'
        '<div class="section-title">DOM Hit Categories</div>'
        '<div class="chart-container"><canvas id="chartDom"></canvas></div>'
        '</div></div>'
        '<div class="col-md-8"><div class="section-card p-3 h-100">'
        '<div class="section-title">Legend</div>'
        '<p class="small text-muted mb-2">Heuristic, regex-based hints to guide '
        'manual review &mdash; not confirmed vulnerabilities. Trace each '
        '<span class="dom-source">source</span> to a '
        '<span class="dom-sink">sink</span> to assess DOM-XSS; review every '
        '<span class="dom-msg">postMessage</span> handler for missing origin '
        'checks.</p>'
        '<ul class="small mb-0">'
        f'<li><span class="dom-sink">Sink</span> &mdash; dangerous write/exec '
        f'({cat_counts.get("Sink", 0)})</li>'
        f'<li><span class="dom-source">Source</span> &mdash; attacker-controllable '
        f'input ({cat_counts.get("Source", 0)})</li>'
        f'<li><span class="dom-msg">postMessage</span> &mdash; cross-origin '
        f'messaging ({cat_counts.get("postMessage", 0)})</li>'
        f'<li><span class="dom-listener">Listener</span> &mdash; addEventListener '
        f'({cat_counts.get("Listener", 0)})</li>'
        '</ul></div></div></div>'
        '<div class="section-card p-3">'
        f'<div class="section-title">DOM Sources, Sinks &amp; Messaging '
        f'({len(dom_findings)})</div>'
        '<table id="tblDom" class="table table-sm w-100">'
        '<thead><tr><th>Type</th><th>Asset</th><th>File</th><th>Line</th>'
        '<th>Pattern</th><th>Match</th><th>Code</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div></div>'
    )

    chart_json = json.dumps({
        "labels": ["Sink", "Source", "postMessage", "Listener"],
        "values": [cat_counts.get("Sink", 0), cat_counts.get("Source", 0),
                   cat_counts.get("postMessage", 0), cat_counts.get("Listener", 0)],
    })
    return tab_button, pane, chart_json


def _write_semgrep_report(findings, root, report_path, dom_findings=None):
    """Render all findings into a single centralized HTML report."""
    dom_findings = dom_findings or []
    by_asset = defaultdict(list)
    for f in findings:
        by_asset[f["asset"]].append(f)

    sev_counts = Counter(f["severity"] for f in findings)
    asset_counts = {a: len(v) for a, v in by_asset.items()}

    rows_all = "\n".join(_finding_row(f, include_asset=True)
                         for f in sorted(findings, key=lambda x: x["sev_weight"]))

    dom_tab_button, dom_pane, chart_dom = _build_dom_section(dom_findings)

    tab_buttons, panes, dt_ids = [], [], ["'#tblAll'"]
    if dom_findings:
        dt_ids.append("'#tblDom'")
    for idx, asset in enumerate(sorted(by_asset)):
        items = sorted(by_asset[asset], key=lambda x: x["sev_weight"])
        pane_id = f"asset-{idx}"
        tbl_id = f"tbl{idx}"
        dt_ids.append(f"'#{tbl_id}'")
        a_high = sum(1 for f in items if f["severity"] == "High")
        badge = (f' <span class="badge sev-high">{a_high}&#9888;</span>'
                 if a_high else "")
        tab_buttons.append(
            f'<li class="nav-item"><button class="nav-link" data-bs-toggle="pill" '
            f'data-bs-target="#{pane_id}">{_esc(asset)} '
            f'<span class="badge bg-secondary">{len(items)}</span></button></li>'
        )
        rows = "\n".join(_finding_row(f, include_asset=False) for f in items)
        panes.append(
            f'<div class="tab-pane fade" id="{pane_id}">'
            f'<div class="section-card p-3">'
            f'<div class="section-title">{_esc(asset)} &mdash; {len(items)} finding(s){badge}</div>'
            f'<table id="{tbl_id}" class="table table-sm w-100">'
            f'<thead><tr><th>Severity</th><th>File</th><th>Line</th>'
            f'<th>Rule</th><th>Message</th><th>OWASP / CWE</th><th>Code</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div></div>'
        )

    chart_severity = json.dumps({
        "labels": ["High", "Medium", "Low"],
        "values": [sev_counts.get("High", 0), sev_counts.get("Medium", 0),
                   sev_counts.get("Low", 0)],
    })
    top_assets = sorted(asset_counts.items(), key=lambda kv: kv[1], reverse=True)[:20]
    chart_assets = json.dumps({
        "labels": [a for a, _ in top_assets],
        "values": [c for _, c in top_assets],
    })

    dom_cat_counts = Counter(d["category"] for d in dom_findings)

    html = _HTML_TEMPLATE.format(
        root=_esc(root),
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_findings=len(findings),
        total_assets=len(by_asset),
        total_high=sev_counts.get("High", 0),
        total_medium=sev_counts.get("Medium", 0),
        total_sinks=dom_cat_counts.get("Sink", 0),
        total_postmessage=dom_cat_counts.get("postMessage", 0),
        rows_all=rows_all,
        dom_tab_button=dom_tab_button,
        dom_pane=dom_pane,
        asset_tab_buttons="\n".join(tab_buttons),
        asset_panes="\n".join(panes),
        datatable_ids="[" + ", ".join(dt_ids) + "]",
        chart_severity_json=chart_severity,
        chart_assets_json=chart_assets,
        chart_dom_json=chart_dom,
    )

    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return report_path


# ──────────────────────────────────────────────────────────────────────────────
# Aggregation + stage entry point
# ──────────────────────────────────────────────────────────────────────────────

def _empty(skip_reason="", report_file=""):
    return {
        "findings": [], "dom_findings": [], "by_asset": {},
        "counts": {"findings": 0, "high": 0, "medium": 0, "low": 0,
                   "dom": 0, "sinks": 0, "sources": 0, "postmessage": 0, "listeners": 0},
        "assets": 0, "report_file": report_file, "semgrep_available": False,
        "skipped": True, "skip_reason": skip_reason,
        "tool_results": [{"tool": "semgrep", "duration": 0.0, "skipped": True,
                          "skip_reason": skip_reason or "no JS to analyze"}],
    }


def _aggregate(findings, dom_findings):
    counts = {"findings": len(findings), "high": 0, "medium": 0, "low": 0,
              "dom": len(dom_findings), "sinks": 0, "sources": 0,
              "postmessage": 0, "listeners": 0}
    by_asset = {}

    def _slot(asset):
        return by_asset.setdefault(asset, {
            "findings": 0, "high": 0, "medium": 0, "low": 0,
            "dom": 0, "sinks": 0, "sources": 0, "postmessage": 0, "listeners": 0})

    for f in findings:
        a = _slot(f["asset"])
        a["findings"] += 1
        sev = f["severity"]
        key = {"High": "high", "Medium": "medium", "Low": "low"}.get(sev, "low")
        a[key] += 1
        counts[key] += 1

    cat_key = {"Sink": "sinks", "Source": "sources",
               "postMessage": "postmessage", "Listener": "listeners"}
    for d in dom_findings:
        a = _slot(d["asset"])
        a["dom"] += 1
        k = cat_key.get(d["category"])
        if k:
            a[k] += 1
            counts[k] += 1

    return counts, by_asset


def _analyze_blocking(root: Path, outdir: Path, cfg: dict) -> dict:
    configs = cfg.get("configs") or CONFIGS
    do_dom = cfg.get("dom_scan", True)
    timeout = cfg.get("timeout")
    if isinstance(timeout, (int, float)) and timeout <= 0:
        timeout = None
    raw_dir = outdir / "semgrep_raw"
    report_path = outdir / "semgrep_report.html"

    dirs = list(find_js_dirs(str(root)))
    if not dirs:
        log.warning("JS analysis: no directories containing *.js under %s", root)
        return _empty("no *.js files found", str(report_path))

    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        log.warning("JS analysis: semgrep not found on PATH — running DOM "
                    "heuristics only (install with: pip install semgrep)")

    log.info("JS analysis: %d director(ies) with *.js under %s", len(dirs), root)

    all_findings, dom_findings, failures = [], [], 0
    for directory in dirs:
        if semgrep_bin:
            rc, results = run_for_directory(semgrep_bin, directory, configs, raw_dir, timeout)
            if rc >= 2 and rc not in (124,):  # 1 = findings present; >=2 = error
                failures += 1
            for r in results:
                all_findings.append(_normalize(r, str(root)))
        if do_dom:
            for js in js_files_in(directory):
                dom_findings.extend(scan_dom_patterns(js, str(root)))

    _write_semgrep_report(all_findings, str(root), str(report_path), dom_findings)

    counts, by_asset = _aggregate(all_findings, dom_findings)
    log.info("JS analysis: %d semgrep finding(s) (high=%d med=%d) + %d DOM hit(s) "
             "(sinks=%d postMessage=%d) across %d asset(s)",
             counts["findings"], counts["high"], counts["medium"], counts["dom"],
             counts["sinks"], counts["postmessage"], len(by_asset))
    log.info("JS analysis: report -> %s", report_path)

    return {
        "findings": all_findings,
        "dom_findings": dom_findings,
        "by_asset": by_asset,
        "counts": counts,
        "assets": len(by_asset),
        "report_file": str(report_path),
        "semgrep_available": bool(semgrep_bin),
        "skipped": False,
        "skip_reason": "" if semgrep_bin else "semgrep not installed (DOM heuristics only)",
        "tool_results": [
            {"tool": "semgrep", "duration": 0.0, "skipped": not bool(semgrep_bin),
             "skip_reason": "" if semgrep_bin else "semgrep not installed"},
            {"tool": "dom-scan", "duration": 0.0, "skipped": not do_dom,
             "skip_reason": "" if do_dom else "disabled in config"},
        ],
    }


async def analyze_js(outdir: Path, cfg: dict, collect_data: dict) -> dict:
    log.info("=== Stage 5: Client-Side JavaScript Analysis (semgrep + DOM) ===")
    acfg = cfg.get("js_analysis", {})
    if not acfg.get("enabled", True):
        log.info("JS analysis: disabled in config — skipping")
        return _empty("disabled in config")

    root = Path(collect_data.get("root") or (outdir / "collected"))
    if not root.exists():
        log.warning("JS analysis: collected directory not found: %s", root)
        return _empty(f"collected directory not found: {root}")

    return await asyncio.to_thread(_analyze_blocking, root, outdir, acfg)
