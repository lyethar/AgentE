"""
Stage 6 — Interactive HTML Report Generation
Produces a self-contained single-file HTML report with:
  - Executive summary dashboard
  - Filterable/sortable DataTables for each section
  - Chart.js visualizations
  - Dark hacker aesthetic
"""
import json
import logging
from datetime import datetime
from pathlib import Path

log = logging.getLogger("agente.reporting")

# ──────────────────────────────────────────────────────────────────────────────
# HTML template (Bootstrap 5 + DataTables + Chart.js, dark theme)
# ──────────────────────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentE — {target}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.datatables.net/2.0.7/css/dataTables.bootstrap5.min.css">
<style>
:root {{
  --accent: #00ff88;
  --accent2: #0dcaf0;
  --bg-card: #0f1117;
  --bg-page: #080b10;
  --border: #1e2940;
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
.badge-source {{ font-size: .7rem; }}
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
  border: 1px solid var(--border) !important; border-radius: 6px;
}}
.dataTables_wrapper .dataTables_info,
.dataTables_wrapper .dataTables_paginate .paginate_button {{
  color: #8899aa !important;
}}
.dataTables_wrapper .dataTables_paginate .paginate_button.current {{
  background: var(--accent) !important; color: #000 !important;
  border-radius: 4px; border: none !important;
}}
.status-200 {{ color: #00ff88; }}
.status-301, .status-302 {{ color: #ffc107; }}
.status-403 {{ color: #fd7e14; }}
.status-404 {{ color: #dc3545; }}
.status-500 {{ color: #6f42c1; }}
.tool-badge-ok {{ background: #0a3d20; color: #00ff88; border: 1px solid #00ff8844; }}
.tool-badge-skip {{ background: #3d200a; color: #ff8800; border: 1px solid #ff880044; }}
.secret-snippet {{ font-family: monospace; font-size: .75rem; color: #ff6b6b;
                   background: #1a0a0a; padding: 4px 8px; border-radius: 4px;
                   border-left: 3px solid #ff6b6b; }}
.chart-container {{ position: relative; height: 260px; }}
.ts {{ color: #556; font-size: .78rem; }}
</style>
</head>
<body>

<nav class="navbar navbar-dark px-4 py-3" style="background:#080b10; border-bottom:1px solid var(--border);">
  <span class="navbar-brand">&#9670; AgentE</span>
  <span class="text-muted small">Target: <strong class="text-info">{target}</strong>
    &nbsp;|&nbsp; Generated: <span class="ts">{generated}</span></span>
</nav>

<div class="container-fluid py-4 px-4">

<!-- SUMMARY CARDS -->
<div class="row g-3 mb-4">
  <div class="col-6 col-md-2">
    <div class="stat-card p-3 text-center">
      <div class="stat-value">{total_subdomains}</div>
      <div class="stat-label">Subdomains</div>
    </div>
  </div>
  <div class="col-6 col-md-2">
    <div class="stat-card p-3 text-center">
      <div class="stat-value">{total_live}</div>
      <div class="stat-label">Live Hosts</div>
    </div>
  </div>
  <div class="col-6 col-md-2">
    <div class="stat-card p-3 text-center">
      <div class="stat-value">{total_endpoints}</div>
      <div class="stat-label">Endpoints</div>
    </div>
  </div>
  <div class="col-6 col-md-2">
    <div class="stat-card p-3 text-center">
      <div class="stat-value">{total_collected}</div>
      <div class="stat-label">JS Collected</div>
    </div>
  </div>
  <div class="col-6 col-md-2">
    <div class="stat-card p-3 text-center">
      <div class="stat-value">{total_cloud}</div>
      <div class="stat-label">Cloud Assets</div>
    </div>
  </div>
  <div class="col-6 col-md-2">
    <div class="stat-card p-3 text-center">
      <div class="stat-value">{total_emails}</div>
      <div class="stat-label">Emails</div>
    </div>
  </div>
  <div class="col-6 col-md-2">
    <div class="stat-card p-3 text-center">
      <div class="stat-value">{total_secrets}</div>
      <div class="stat-label">Secrets &#9888;</div>
    </div>
  </div>
</div>

<!-- CHARTS ROW -->
<div class="row g-3 mb-4">
  <div class="col-md-4">
    <div class="section-card p-3">
      <div class="section-title">Subdomain Sources</div>
      <div class="chart-container"><canvas id="chartSources"></canvas></div>
    </div>
  </div>
  <div class="col-md-4">
    <div class="section-card p-3">
      <div class="section-title">HTTP Status Codes</div>
      <div class="chart-container"><canvas id="chartStatus"></canvas></div>
    </div>
  </div>
  <div class="col-md-4">
    <div class="section-card p-3">
      <div class="section-title">Tool Execution</div>
      <div class="chart-container"><canvas id="chartTools"></canvas></div>
    </div>
  </div>
</div>

<!-- TABS -->
<ul class="nav nav-pills mb-3" id="mainTabs">
  <li class="nav-item"><button class="nav-link active" data-bs-toggle="pill" data-bs-target="#tab-subs">Subdomains</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#tab-live">Live Hosts</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#tab-ep">Endpoints</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#tab-collected">Collected Assets</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#tab-cloud">Cloud</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#tab-email">Email Intel</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#tab-secrets">Secrets &#9888;</button></li>
</ul>

<div class="tab-content">

<!-- SUBDOMAINS -->
<div class="tab-pane fade show active" id="tab-subs">
  <div class="section-card p-3">
    <div class="section-title">Discovered Subdomains</div>
    <table id="tblSubs" class="table table-sm w-100">
      <thead><tr><th>Subdomain</th><th>Sources</th></tr></thead>
      <tbody>{rows_subdomains}</tbody>
    </table>
  </div>
</div>

<!-- LIVE HOSTS -->
<div class="tab-pane fade" id="tab-live">
  <div class="section-card p-3">
    <div class="section-title">HTTP Live Hosts</div>
    <table id="tblLive" class="table table-sm w-100">
      <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Tech</th><th>IP</th></tr></thead>
      <tbody>{rows_live}</tbody>
    </table>
  </div>
</div>

<!-- ENDPOINTS -->
<div class="tab-pane fade" id="tab-ep">
  <div class="section-card p-3">
    <div class="section-title">Discovered Endpoints</div>
    <ul class="nav nav-tabs mb-3" id="epTabs">
      <li class="nav-item"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#ep-all">All ({total_endpoints})</button></li>
      <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#ep-js">JS Files ({total_js})</button></li>
      <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#ep-api">API Paths ({total_api})</button></li>
    </ul>
    <div class="tab-content">
      <div class="tab-pane fade show active" id="ep-all">
        <table id="tblEp" class="table table-sm w-100">
          <thead><tr><th>Endpoint</th></tr></thead>
          <tbody>{rows_endpoints}</tbody>
        </table>
      </div>
      <div class="tab-pane fade" id="ep-js">
        <table id="tblJs" class="table table-sm w-100">
          <thead><tr><th>JS File</th></tr></thead>
          <tbody>{rows_js}</tbody>
        </table>
      </div>
      <div class="tab-pane fade" id="ep-api">
        <table id="tblApi" class="table table-sm w-100">
          <thead><tr><th>API Path</th></tr></thead>
          <tbody>{rows_api}</tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<!-- COLLECTED ASSETS -->
<div class="tab-pane fade" id="tab-collected">
  <div class="section-card p-3">
    <div class="section-title">Collected Assets &mdash; Downloaded for Client-Side Inspection</div>
    <p class="text-muted small">
      JavaScript, JSON, and config files downloaded into per-asset directories under
      <code>collected/</code>. Downloaded: <strong class="text-success">{collected_ok}</strong> &nbsp;|&nbsp;
      Skipped: <strong class="text-warning">{collected_skip}</strong> &nbsp;|&nbsp;
      Failed: <strong class="text-danger">{collected_fail}</strong>
    </p>
    <table id="tblCollected" class="table table-sm w-100">
      <thead><tr><th>Asset (Domain)</th><th>JS</th><th>JSON</th><th>Config</th><th>Total</th></tr></thead>
      <tbody>{rows_collected}</tbody>
    </table>
  </div>
</div>

<!-- CLOUD -->
<div class="tab-pane fade" id="tab-cloud">
  <div class="section-card p-3">
    <div class="section-title">Cloud Infrastructure</div>
    <div class="row g-3">
      <div class="col-md-6">
        <h6 class="text-warning">&#x2601; AWS S3 Buckets ({cnt_s3})</h6>
        <table id="tblS3" class="table table-sm w-100">
          <thead><tr><th>Bucket / URL</th></tr></thead>
          <tbody>{rows_s3}</tbody>
        </table>
      </div>
      <div class="col-md-6">
        <h6 class="text-info">&#x2601; Azure Blob Storage ({cnt_azure})</h6>
        <table id="tblAzure" class="table table-sm w-100">
          <thead><tr><th>Container / URL</th></tr></thead>
          <tbody>{rows_azure}</tbody>
        </table>
      </div>
      <div class="col-md-6">
        <h6 class="text-success">&#x2601; GCP Storage ({cnt_gcp})</h6>
        <table id="tblGcp" class="table table-sm w-100">
          <thead><tr><th>Bucket / URL</th></tr></thead>
          <tbody>{rows_gcp}</tbody>
        </table>
      </div>
      <div class="col-md-6">
        <h6 class="text-danger">&#x26A1; Serverless Functions ({cnt_func})</h6>
        <table id="tblFunc" class="table table-sm w-100">
          <thead><tr><th>Endpoint</th></tr></thead>
          <tbody>{rows_func}</tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<!-- EMAIL -->
<div class="tab-pane fade" id="tab-email">
  <div class="section-card p-3">
    <div class="section-title">Email & Username Intelligence</div>
    <div class="row g-3">
      <div class="col-md-6">
        <h6 class="text-success">Email Addresses ({total_emails})</h6>
        <table id="tblEmails" class="table table-sm w-100">
          <thead><tr><th>Email</th><th>Source</th></tr></thead>
          <tbody>{rows_emails}</tbody>
        </table>
      </div>
      <div class="col-md-6">
        <h6 class="text-info">LinkedIn Usernames ({total_usernames})</h6>
        <table id="tblUsers" class="table table-sm w-100">
          <thead><tr><th>Username</th></tr></thead>
          <tbody>{rows_usernames}</tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<!-- SECRETS -->
<div class="tab-pane fade" id="tab-secrets">
  <div class="section-card p-3">
    <div class="section-title">&#9888; Potential Secrets & Sensitive Patterns</div>
    <p class="text-muted small">Regex-matched patterns from crawled JS/pages. Verify manually.</p>
    <table id="tblSecrets" class="table table-sm w-100">
      <thead><tr><th>File</th><th>Pattern Match</th></tr></thead>
      <tbody>{rows_secrets}</tbody>
    </table>
  </div>
</div>

</div><!-- end tab-content -->
</div><!-- end container -->

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/2.0.7/js/dataTables.min.js"></script>
<script src="https://cdn.datatables.net/2.0.7/js/dataTables.bootstrap5.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<script>
$(function() {{
  const dtOpts = {{ pageLength: 25, lengthMenu: [25, 50, 100, 500] }};
  ['#tblSubs','#tblLive','#tblEp','#tblJs','#tblApi','#tblCollected',
   '#tblS3','#tblAzure','#tblGcp','#tblFunc',
   '#tblEmails','#tblUsers','#tblSecrets'].forEach(id => {{
    if ($(id).length) $(id).DataTable(dtOpts);
  }});

  // Chart: Subdomain Sources
  const srcData = {chart_sources_json};
  new Chart(document.getElementById('chartSources'), {{
    type: 'doughnut',
    data: {{
      labels: srcData.labels,
      datasets: [{{ data: srcData.values,
        backgroundColor: ['#00ff88','#0dcaf0','#6f42c1','#fd7e14'],
        borderWidth: 0 }}]
    }},
    options: {{ plugins: {{ legend: {{ labels: {{ color: '#cdd9e5' }} }} }}, cutout: '65%' }}
  }});

  // Chart: HTTP Status Codes
  const stData = {chart_status_json};
  new Chart(document.getElementById('chartStatus'), {{
    type: 'bar',
    data: {{
      labels: stData.labels,
      datasets: [{{ data: stData.values, backgroundColor: stData.colors, borderWidth: 0 }}]
    }},
    options: {{
      plugins: {{ legend: {{ display: false }} }},
      scales: {{
        x: {{ ticks: {{ color: '#8899aa' }}, grid: {{ color: '#1e2940' }} }},
        y: {{ ticks: {{ color: '#8899aa' }}, grid: {{ color: '#1e2940' }} }}
      }}
    }}
  }});

  // Chart: Tool Durations
  const toolData = {chart_tools_json};
  new Chart(document.getElementById('chartTools'), {{
    type: 'horizontalBar',
    data: {{
      labels: toolData.labels,
      datasets: [{{
        data: toolData.values,
        backgroundColor: toolData.colors,
        borderWidth: 0
      }}]
    }},
    options: {{
      indexAxis: 'y',
      plugins: {{ legend: {{ display: false }} }},
      scales: {{
        x: {{ ticks: {{ color: '#8899aa' }}, grid: {{ color: '#1e2940' }},
              title: {{ display: true, text: 'seconds', color: '#556' }} }},
        y: {{ ticks: {{ color: '#8899aa' }}, grid: {{ color: '#1e2940' }} }}
      }}
    }}
  }});
}});
</script>
</body>
</html>
"""


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def _status_class(code: int) -> str:
    if code < 300:   return "status-200"
    if code < 400:   return "status-301"
    if code == 403:  return "status-403"
    if code < 500:   return "status-404"
    return "status-500"


def _status_color(code: int) -> str:
    if code < 300:   return "#00ff88"
    if code < 400:   return "#ffc107"
    if code == 403:  return "#fd7e14"
    if code < 500:   return "#dc3545"
    return "#6f42c1"


def _rows(items: list[str], extra_cols: list[str] | None = None) -> str:
    rows = []
    for item in items:
        cells = f"<td>{_esc(item)}</td>"
        if extra_cols:
            cells += "".join(f"<td>{c}</td>" for c in extra_cols)
        rows.append(f"<tr>{cells}</tr>")
    return "\n".join(rows)


def _build_chart_sources(by_tool: dict[str, list]) -> str:
    labels = list(by_tool.keys())
    values = [len(v) for v in by_tool.values()]
    return json.dumps({"labels": labels, "values": values})


def _build_chart_status(hosts: list[dict]) -> str:
    counts: dict[int, int] = {}
    for h in hosts:
        code = h.get("status_code", 0)
        counts[code] = counts.get(code, 0) + 1
    labels = [str(k) for k in sorted(counts)]
    values = [counts[int(k)] for k in labels]
    colors = [_status_color(int(k)) for k in labels]
    return json.dumps({"labels": labels, "values": values, "colors": colors})


def _build_chart_tools(all_tool_results: list[dict]) -> str:
    seen: dict[str, float] = {}
    for r in all_tool_results:
        name = r["tool"]
        if name not in seen:
            seen[name] = round(r.get("duration", 0), 1)
    labels = list(seen.keys())
    values = list(seen.values())
    colors = ["#00ff88" if not all_tool_results[i].get("skipped") else "#ff6600"
              for i, name in enumerate(labels)]
    return json.dumps({"labels": labels, "values": values, "colors": colors})


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def generate_report(
    domain: str,
    outdir: Path,
    sub_data:     dict,
    val_data:     dict,
    js_data:      dict,
    collect_data: dict,
    cloud_data:   dict,
    email_data:   dict,
) -> Path:
    log.info("=== Stage 7: Generating HTML Report ===")

    # ── Subdomains ──
    subs_by_tool: dict[str, list] = sub_data.get("by_tool", {})
    all_subs = sub_data.get("all", [])
    sub_source_map: dict[str, list[str]] = {}
    for tool, subs in subs_by_tool.items():
        for s in subs:
            sub_source_map.setdefault(s, []).append(tool)
    for s in all_subs:
        sub_source_map.setdefault(s, ["?"])

    rows_subdomains = "\n".join(
        f'<tr><td>{_esc(s)}</td><td>'
        + " ".join(f'<span class="badge badge-source bg-secondary">{_esc(t)}</span>'
                   for t in sub_source_map.get(s, []))
        + "</td></tr>"
        for s in sorted(sub_source_map)
    )

    # ── Live Hosts ──
    hosts = val_data.get("live_hosts", [])
    rows_live_parts = []
    for h in hosts:
        url     = _esc(h.get("url", ""))
        code    = h.get("status_code", 0)
        title   = _esc(h.get("title", ""))
        tech    = ", ".join(h.get("tech", []) or [])
        ip      = _esc(h.get("host", ""))
        sc      = _status_class(code)
        rows_live_parts.append(
            f'<tr><td><a href="{url}" target="_blank">{url}</a></td>'
            f'<td class="{sc}">{code}</td><td>{title}</td>'
            f'<td>{_esc(tech)}</td><td>{ip}</td></tr>'
        )
    rows_live = "\n".join(rows_live_parts)

    # ── Endpoints ──
    endpoints = js_data.get("endpoints", [])
    js_files  = js_data.get("js_files", [])
    api_paths = js_data.get("api_paths", [])
    rows_endpoints = _rows(endpoints)
    rows_js        = _rows(js_files)
    rows_api       = _rows(api_paths)

    # ── Collected Assets ──
    collect_counts  = collect_data.get("counts", {})
    by_asset        = collect_data.get("by_asset", {})
    rows_collected = "\n".join(
        f'<tr><td>{_esc(asset)}</td>'
        f'<td>{a.get("js", 0)}</td><td>{a.get("json", 0)}</td>'
        f'<td>{a.get("config", 0)}</td><td>{a.get("total", 0)}</td></tr>'
        for asset, a in sorted(by_asset.items())
    )

    # ── Cloud ──
    assets   = cloud_data.get("assets", {})
    rows_s3    = _rows(assets.get("s3", []))
    rows_azure = _rows(assets.get("azure", []))
    rows_gcp   = _rows(assets.get("gcp", []))
    rows_func  = _rows(assets.get("functions", []))

    # ── Email ──
    all_emails = email_data.get("emails", [])
    usernames  = email_data.get("usernames", [])
    pb_count   = email_data.get("phonebooks_count", 0)
    li_count   = email_data.get("linkedin_count", 0)

    rows_emails_parts = []
    for e in all_emails:
        source = "phonebooks.cz" if "@" in e and all_emails.index(e) < pb_count else "linkedin"
        rows_emails_parts.append(
            f'<tr><td>{_esc(e)}</td><td><span class="badge bg-secondary">{source}</span></td></tr>'
        )
    rows_emails    = "\n".join(rows_emails_parts)
    rows_usernames = _rows(usernames)

    # ── Secrets ──
    secrets = js_data.get("potential_secrets", [])
    rows_secrets = "\n".join(
        f'<tr><td class="text-muted small">{_esc(s["file"])}</td>'
        f'<td><div class="secret-snippet">{_esc(s["snippet"][:150])}</div></td></tr>'
        for s in secrets
    )

    # ── Charts ──
    all_tool_results = (
        sub_data.get("tool_results", [])
        + val_data.get("tool_results", [])
        + js_data.get("tool_results", [])
        + collect_data.get("tool_results", [])
        + cloud_data.get("tool_results", [])
        + email_data.get("tool_results", [])
    )

    html = _HTML_TEMPLATE.format(
        target=_esc(domain),
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_subdomains=len(all_subs),
        total_live=len(hosts),
        total_endpoints=len(endpoints),
        total_collected=collect_counts.get("downloaded", 0),
        collected_ok=collect_counts.get("downloaded", 0),
        collected_skip=collect_counts.get("skipped", 0),
        collected_fail=collect_counts.get("failed", 0),
        rows_collected=rows_collected,
        total_cloud=cloud_data.get("total", 0),
        total_emails=len(all_emails),
        total_secrets=len(secrets),
        total_js=len(js_files),
        total_api=len(api_paths),
        total_usernames=len(usernames),
        cnt_s3=len(assets.get("s3", [])),
        cnt_azure=len(assets.get("azure", [])),
        cnt_gcp=len(assets.get("gcp", [])),
        cnt_func=len(assets.get("functions", [])),
        rows_subdomains=rows_subdomains,
        rows_live=rows_live,
        rows_endpoints=rows_endpoints,
        rows_js=rows_js,
        rows_api=rows_api,
        rows_s3=rows_s3,
        rows_azure=rows_azure,
        rows_gcp=rows_gcp,
        rows_func=rows_func,
        rows_emails=rows_emails,
        rows_usernames=rows_usernames,
        rows_secrets=rows_secrets,
        chart_sources_json=_build_chart_sources(subs_by_tool),
        chart_status_json=_build_chart_status(hosts),
        chart_tools_json=_build_chart_tools(all_tool_results),
    )

    report_path = outdir / f"report_{domain}.html"
    report_path.write_text(html, encoding="utf-8")
    log.info("Report written to: %s", report_path)
    return report_path
