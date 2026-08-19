"""
Shared HTML report shell.

AgentE splits its output into one self-contained HTML file per stage (instead of
a single mega-report) so no page is overloaded. Every page shares the same dark
theme, top navigation and DataTables/Chart.js wiring defined here, so the split
reports look and behave consistently and can link to one another.

Usage:
    from utils.htmlreport import page, esc, NAV
    html = page(target="example.com", active="01-subdomains.html",
                subtitle="Subdomains", body="<table>...</table>")
"""
from datetime import datetime

# ── Canonical navigation shared by every report page ──────────────────────────
# (filename, label). The filenames are the split report files written into the
# run's reports/ directory. A page links to the others by bare filename.
NAV: list[tuple[str, str]] = [
    ("index.html",          "Overview"),
    ("01-subdomains.html",  "Subdomains"),
    ("02-live-hosts.html",  "Live Hosts"),
    ("03-nuclei.html",      "Nuclei"),
    ("04-endpoints.html",   "Endpoints"),
    ("05-assets.html",      "Assets"),
    ("06-js-analysis.html", "JS Analysis"),
    ("07-cloud.html",       "Cloud"),
    ("08-email.html",       "Email"),
    ("09-exposure.html",    "Exposure"),
    ("ip-fqdn.html",        "IP→FQDN"),
    ("secrets.html",        "Secrets"),
]


def esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


_CSS = """\
:root {
  --accent: #00ff88; --accent2: #0dcaf0;
  --bg-card: #0f1117; --bg-page: #080b10; --border: #1e2940;
}
body { background: var(--bg-page); font-family: 'Segoe UI', system-ui, sans-serif; }
.navbar-brand { color: var(--accent) !important; font-weight: 700; letter-spacing: 2px; }
.report-nav { background:#0a0d14; border-bottom:1px solid var(--border); }
.report-nav a { color:#8899aa; text-decoration:none; padding:.35rem .8rem; border-radius:6px;
                font-size:.85rem; white-space:nowrap; }
.report-nav a:hover { color:#cdd9e5; background:#131822; }
.report-nav a.active { color:#000; background:var(--accent); font-weight:600; }
.stat-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
             transition: transform .2s; }
.stat-card:hover { transform: translateY(-3px); }
.stat-value { font-size: 2.4rem; font-weight: 700; color: var(--accent); }
.stat-label { color: #8899aa; font-size: .85rem; text-transform: uppercase; letter-spacing: 1px; }
.section-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; }
.section-title { color: var(--accent2); font-weight: 600; border-bottom: 1px solid var(--border);
                 padding-bottom: .5rem; margin-bottom: 1rem; }
.badge-source { font-size: .7rem; }
.nav-pills .nav-link.active { background: var(--accent); color: #000 !important; font-weight: 600; }
.nav-pills .nav-link { color: #aaa; }
table.dataTable { background: var(--bg-card) !important; }
table.dataTable thead th { background: #0a0d14 !important; color: var(--accent2) !important;
                            border-bottom: 2px solid var(--border) !important; }
table.dataTable tbody tr { background: var(--bg-card) !important; color: #cdd9e5; }
table.dataTable tbody tr:hover { background: #131822 !important; }
.dataTables_wrapper .dataTables_filter input,
.dataTables_wrapper .dataTables_length select {
  background: #131822 !important; color: #cdd9e5 !important;
  border: 1px solid var(--border) !important; border-radius: 6px; }
.dataTables_wrapper .dataTables_info,
.dataTables_wrapper .dataTables_paginate .paginate_button { color: #8899aa !important; }
.dataTables_wrapper .dataTables_paginate .paginate_button.current {
  background: var(--accent) !important; color: #000 !important;
  border-radius: 4px; border: none !important; }
.status-200, .sev-info { color: #00ff88; }
.status-301, .status-302 { color: #ffc107; }
.status-403 { color: #fd7e14; }
.status-404 { color: #dc3545; }
.status-500 { color: #6f42c1; }
.sev-critical { color: #ff2d55; font-weight: 700; }
.sev-high { color: #ff4d4d; font-weight: 700; }
.sev-medium { color: #ffc107; font-weight: 600; }
.sev-low { color: #0dcaf0; }
.sev-unknown { color: #8899aa; }
.tool-badge-ok { background: #0a3d20; color: #00ff88; border: 1px solid #00ff8844; }
.tool-badge-skip { background: #3d200a; color: #ff8800; border: 1px solid #ff880044; }
.secret-snippet { font-family: monospace; font-size: .75rem; color: #ff6b6b;
                  background: #1a0a0a; padding: 4px 8px; border-radius: 4px;
                  border-left: 3px solid #ff6b6b; }
.code-snippet { font-family: monospace; font-size: .75rem; color: #cdd9e5;
                background: #131822; padding: 4px 8px; border-radius: 4px;
                border-left: 3px solid var(--accent2); white-space: pre-wrap;
                max-width: 480px; display: inline-block; }
.match-tag { font-family: monospace; font-size: .74rem; color: #ffd166;
             background: #1a1500; padding: 2px 6px; border-radius: 4px; }
.chart-container { position: relative; height: 260px; }
.ts { color: #556; font-size: .78rem; }
.js-flag { color:#ffd166; font-weight:600; }
"""

_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentE — {subtitle} — {target}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.datatables.net/2.0.7/css/dataTables.bootstrap5.min.css">
<style>
{css}
{extra_head}
</style>
</head>
<body>

<nav class="navbar navbar-dark px-4 py-3" style="background:#080b10; border-bottom:1px solid var(--border);">
  <span class="navbar-brand">&#9670; AgentE</span>
  <span class="text-muted small">{subtitle} &nbsp;|&nbsp; Target:
    <strong class="text-info">{target}</strong>
    &nbsp;|&nbsp; Generated: <span class="ts">{generated}</span></span>
</nav>

<div class="report-nav d-flex flex-wrap gap-1 px-4 py-2">
{nav_links}
</div>

<div class="container-fluid py-4 px-4">
{body}
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/2.0.7/js/dataTables.min.js"></script>
<script src="https://cdn.datatables.net/2.0.7/js/dataTables.bootstrap5.min.js"></script>
{chart_lib}
<script>
$(function() {{
  const dtOpts = {{ pageLength: 25, lengthMenu: [25, 50, 100, 500] }};
  // Every table tagged .dt becomes a DataTable automatically.
  $('table.dt').each(function() {{ $(this).DataTable(dtOpts); }});
{extra_script}
}});
</script>
</body>
</html>
"""

_CHART_LIB = ('<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/'
              'dist/chart.umd.min.js"></script>')


def _nav_links(active: str) -> str:
    parts = []
    for filename, label in NAV:
        cls = "active" if filename == active else ""
        parts.append(f'<a class="{cls}" href="{filename}">{label}</a>')
    return "\n".join(parts)


def page(target: str, active: str, subtitle: str, body: str,
         with_charts: bool = False, extra_head: str = "",
         extra_script: str = "") -> str:
    """Wrap *body* HTML in the shared page shell and return the full document."""
    return _TEMPLATE.format(
        target=esc(target),
        subtitle=esc(subtitle),
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        css=_CSS,
        extra_head=extra_head,
        nav_links=_nav_links(active),
        body=body,
        chart_lib=_CHART_LIB if with_charts else "",
        extra_script=extra_script,
    )
