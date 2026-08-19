"""
Stage 10 — HTML Report Generation (split, one file per stage)

Historically AgentE produced a single, enormous tabbed HTML file. That page grew
unwieldy, so results are now split into one self-contained HTML report per
stage, all written into the run's ``reports/`` directory and sharing the common
shell defined in ``utils.htmlreport``:

    reports/
      index.html            executive dashboard + links to every sub-report
      01-subdomains.html
      02-live-hosts.html
      03-nuclei.html        (written by Stage 3 / recon_scan)
      04-endpoints.html     endpoints + JS + API + waymore catalog
      05-assets.html
      06-js-analysis.html   (written by Stage 6 / js_analysis)
      07-cloud.html
      08-email.html
      09-exposure.html
      ip-fqdn.html
      secrets.html

``generate_report`` writes the pages it owns and returns the path to
``index.html`` (the entry point).
"""
import json
import logging
from pathlib import Path

from utils.htmlreport import NAV, esc, page

log = logging.getLogger("agente.reporting")


# ──────────────────────────────────────────────────────────────────────────────
# Small helpers
# ──────────────────────────────────────────────────────────────────────────────

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


def _rows(items: list[str]) -> str:
    return "\n".join(f"<tr><td>{esc(item)}</td></tr>" for item in items)


def _card(value, label, cls="") -> str:
    return (f'<div class="col-6 col-md-2">'
            f'<div class="stat-card p-3 text-center">'
            f'<div class="stat-value {cls}">{value}</div>'
            f'<div class="stat-label">{label}</div></div></div>')


def _section(title: str, table_html: str, note: str = "") -> str:
    note_html = f'<p class="text-muted small">{note}</p>' if note else ""
    return (f'<div class="section-card p-3">'
            f'<div class="section-title">{title}</div>{note_html}{table_html}</div>')


# ──────────────────────────────────────────────────────────────────────────────
# Chart data builders (index only)
# ──────────────────────────────────────────────────────────────────────────────

def _chart_sources(by_tool: dict[str, list]) -> str:
    return json.dumps({"labels": list(by_tool.keys()),
                       "values": [len(v) for v in by_tool.values()]})


def _chart_status(hosts: list[dict]) -> str:
    counts: dict[int, int] = {}
    for h in hosts:
        code = h.get("status_code", 0)
        counts[code] = counts.get(code, 0) + 1
    labels = [str(k) for k in sorted(counts)]
    return json.dumps({"labels": labels,
                       "values": [counts[int(k)] for k in labels],
                       "colors": [_status_color(int(k)) for k in labels]})


def _chart_nuclei(counts: dict) -> str:
    labels = ["Critical", "High", "Medium", "Low", "Info"]
    keys   = ["critical", "high", "medium", "low", "info"]
    return json.dumps({"labels": labels,
                       "values": [counts.get(k, 0) for k in keys],
                       "colors": ["#ff2d55", "#ff4d4d", "#ffc107", "#0dcaf0", "#00ff88"]})


def _chart_tools(all_tool_results: list[dict]) -> str:
    seen: dict[str, float] = {}
    skipped: dict[str, bool] = {}
    for r in all_tool_results:
        name = r["tool"]
        if name not in seen:
            seen[name] = round(r.get("duration", 0), 1)
            skipped[name] = r.get("skipped", False)
    labels = list(seen.keys())
    return json.dumps({"labels": labels,
                       "values": [seen[n] for n in labels],
                       "colors": ["#ff6600" if skipped[n] else "#00ff88" for n in labels]})


# ──────────────────────────────────────────────────────────────────────────────
# Individual stage pages
# ──────────────────────────────────────────────────────────────────────────────

def _page_subdomains(domain: str, sub_data: dict) -> str:
    subs_by_tool: dict[str, list] = sub_data.get("by_tool", {})
    all_subs = sub_data.get("all", [])
    source_map: dict[str, list[str]] = {}
    for tool, subs in subs_by_tool.items():
        for s in subs:
            source_map.setdefault(s, []).append(tool)
    for s in all_subs:
        source_map.setdefault(s, ["?"])

    rows = "\n".join(
        f'<tr><td>{esc(s)}</td><td>'
        + " ".join(f'<span class="badge badge-source bg-secondary">{esc(t)}</span>'
                   for t in source_map.get(s, []))
        + "</td></tr>"
        for s in sorted(source_map)
    )
    table = ('<table class="table table-sm w-100 dt">'
             '<thead><tr><th>Subdomain</th><th>Sources</th></tr></thead>'
             f'<tbody>{rows}</tbody></table>')
    body = _section(f"Discovered Subdomains ({len(source_map)})", table)
    return page(domain, "01-subdomains.html", "Subdomains", body)


def _page_live_hosts(domain: str, val_data: dict) -> str:
    hosts = val_data.get("live_hosts", [])
    parts = []
    for h in hosts:
        url   = esc(h.get("url", ""))
        code  = h.get("status_code", 0)
        title = esc(h.get("title", ""))
        tech  = esc(", ".join(h.get("tech", []) or []))
        ip    = esc(h.get("host", ""))
        parts.append(
            f'<tr><td><a href="{url}" target="_blank">{url}</a></td>'
            f'<td class="{_status_class(code)}">{code}</td><td>{title}</td>'
            f'<td>{tech}</td><td>{ip}</td></tr>'
        )
    table = ('<table class="table table-sm w-100 dt">'
             '<thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Tech</th><th>IP</th></tr></thead>'
             f'<tbody>{"".join(parts)}</tbody></table>')
    body = _section(f"HTTP Live Hosts ({len(hosts)})", table)
    return page(domain, "02-live-hosts.html", "Live Hosts", body)


def _page_endpoints(domain: str, js_data: dict) -> str:
    endpoints    = js_data.get("endpoints", [])
    js_files     = set(js_data.get("js_files", []))
    api_paths    = js_data.get("api_paths", [])
    waymore_urls = js_data.get("waymore_urls", [])
    waymore_js   = set(js_data.get("waymore_js", []))

    ep_table = ('<table class="table table-sm w-100 dt">'
                '<thead><tr><th>Endpoint</th><th>JS?</th></tr></thead><tbody>'
                + "\n".join(
                    f'<tr><td>{esc(u)}</td><td>'
                    + ('<span class="js-flag">JS</span>' if u in js_files else '')
                    + '</td></tr>'
                    for u in endpoints)
                + '</tbody></table>')
    js_table = ('<table class="table table-sm w-100 dt">'
                '<thead><tr><th>JS File</th></tr></thead>'
                f'<tbody>{_rows(sorted(js_files))}</tbody></table>')
    api_table = ('<table class="table table-sm w-100 dt">'
                 '<thead><tr><th>API Path</th></tr></thead>'
                 f'<tbody>{_rows(api_paths)}</tbody></table>')
    # waymore catalog — historical URLs, JS flagged
    wm_table = ('<table class="table table-sm w-100 dt">'
                '<thead><tr><th>Archived URL (waymore)</th><th>JS?</th></tr></thead><tbody>'
                + "\n".join(
                    f'<tr><td>{esc(u)}</td><td>'
                    + ('<span class="js-flag">JS</span>' if u in waymore_js else '')
                    + '</td></tr>'
                    for u in waymore_urls)
                + '</tbody></table>')

    body = f"""
<ul class="nav nav-pills mb-3 flex-wrap">
  <li class="nav-item"><button class="nav-link active" data-bs-toggle="pill" data-bs-target="#ep-all">All Endpoints ({len(endpoints)})</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#ep-js">JS Files ({len(js_files)})</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#ep-api">API Paths ({len(api_paths)})</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#ep-wm">waymore Archive ({len(waymore_urls)}, JS={len(waymore_js)})</button></li>
</ul>
<div class="tab-content">
  <div class="tab-pane fade show active" id="ep-all">{_section("Discovered Endpoints", ep_table, "JS files are flagged and downloaded in Stage 5 for analysis in Stage 6.")}</div>
  <div class="tab-pane fade" id="ep-js">{_section("JavaScript Files", js_table)}</div>
  <div class="tab-pane fade" id="ep-api">{_section("API Paths", api_table)}</div>
  <div class="tab-pane fade" id="ep-wm">{_section("waymore — Archived / Historical URLs", wm_table, "Pulled from Wayback and other archives. JS-flagged entries are collected and analysed downstream.")}</div>
</div>
"""
    return page(domain, "04-endpoints.html", "Endpoints", body)


def _page_assets(domain: str, collect_data: dict) -> str:
    counts   = collect_data.get("counts", {})
    by_asset = collect_data.get("by_asset", {})
    rows = "\n".join(
        f'<tr><td>{esc(asset)}</td><td>{a.get("js", 0)}</td>'
        f'<td>{a.get("json", 0)}</td><td>{a.get("config", 0)}</td>'
        f'<td>{a.get("total", 0)}</td></tr>'
        for asset, a in sorted(by_asset.items())
    )
    note = (f'Downloaded: <strong class="text-success">{counts.get("downloaded", 0)}</strong> &nbsp;|&nbsp; '
            f'Skipped: <strong class="text-warning">{counts.get("skipped", 0)}</strong> &nbsp;|&nbsp; '
            f'Failed: <strong class="text-danger">{counts.get("failed", 0)}</strong>')
    table = ('<table class="table table-sm w-100 dt">'
             '<thead><tr><th>Asset (Domain)</th><th>JS</th><th>JSON</th><th>Config</th><th>Total</th></tr></thead>'
             f'<tbody>{rows}</tbody></table>')
    body = _section("Collected Assets — Downloaded for Client-Side Inspection", table, note)
    return page(domain, "05-assets.html", "Assets", body)


def _page_cloud(domain: str, cloud_data: dict) -> str:
    assets = cloud_data.get("assets", {})

    def tbl(header, items):
        return (f'<h6 class="text-info">{header} ({len(items)})</h6>'
                '<table class="table table-sm w-100 dt">'
                f'<thead><tr><th>{esc(header)}</th></tr></thead>'
                f'<tbody>{_rows(items)}</tbody></table>')

    grid = (
        '<div class="row g-3">'
        f'<div class="col-md-6">{tbl("AWS S3 Buckets", assets.get("s3", []))}</div>'
        f'<div class="col-md-6">{tbl("Azure Blob Storage", assets.get("azure", []))}</div>'
        f'<div class="col-md-6">{tbl("GCP Storage", assets.get("gcp", []))}</div>'
        f'<div class="col-md-6">{tbl("Serverless Functions", assets.get("functions", []))}</div>'
        '</div>'
    )
    body = _section(f"Cloud Infrastructure ({cloud_data.get('total', 0)})", grid)
    return page(domain, "07-cloud.html", "Cloud", body)


def _page_email(domain: str, email_data: dict) -> str:
    emails    = email_data.get("emails", [])
    usernames = email_data.get("usernames", [])
    pb_count  = email_data.get("phonebooks_count", 0)

    email_rows = []
    for e in emails:
        source = "phonebooks.cz" if "@" in e and emails.index(e) < pb_count else "linkedin"
        email_rows.append(
            f'<tr><td>{esc(e)}</td><td><span class="badge bg-secondary">{source}</span></td></tr>')
    email_tbl = ('<table class="table table-sm w-100 dt">'
                 '<thead><tr><th>Email</th><th>Source</th></tr></thead>'
                 f'<tbody>{"".join(email_rows)}</tbody></table>')
    user_tbl = ('<table class="table table-sm w-100 dt">'
                '<thead><tr><th>Username</th></tr></thead>'
                f'<tbody>{_rows(usernames)}</tbody></table>')
    grid = (
        '<div class="row g-3">'
        f'<div class="col-md-6"><h6 class="text-success">Email Addresses ({len(emails)})</h6>{email_tbl}</div>'
        f'<div class="col-md-6"><h6 class="text-info">LinkedIn Usernames ({len(usernames)})</h6>{user_tbl}</div>'
        '</div>'
    )
    body = _section("Email &amp; Username Intelligence", grid)
    return page(domain, "08-email.html", "Email", body)


def _pick(d: dict, *keys: str) -> str:
    for k in keys:
        for actual in d:
            if actual.lower() == k:
                return str(d[actual])
    return ""


def _page_exposure(domain: str, exposure_data: dict) -> str:
    leakix   = exposure_data.get("leakix", {}) or {}
    gitminer = exposure_data.get("gitminer", {}) or {}
    gdorks   = exposure_data.get("google_dorks", {}) or {}

    leakix_rows = "\n".join(
        f'<tr><td>{esc(r.get("host",""))}</td><td>{esc(r.get("ip",""))}</td>'
        f'<td>{esc(r.get("event",""))}</td><td>{esc(r.get("summary",""))}</td>'
        f'<td class="ts">{esc(r.get("date",""))}</td></tr>'
        for r in leakix.get("results", []) if isinstance(r, dict)
    )
    leakix_tbl = ('<table class="table table-sm w-100 dt">'
                  '<thead><tr><th>Host</th><th>IP</th><th>Event</th><th>Summary</th><th>Date</th></tr></thead>'
                  f'<tbody>{leakix_rows}</tbody></table>')

    github_rows = []
    for f in gitminer.get("findings", []):
        if not isinstance(f, dict):
            continue
        repo  = _pick(f, "repository", "repo", "file", "filename", "name", "path")
        url   = _pick(f, "url", "html_url", "link")
        match = _pick(f, "match", "dork", "query", "matched", "snippet")
        url_cell = f'<a href="{esc(url)}" target="_blank">{esc(url)}</a>' if url else ""
        github_rows.append(f'<tr><td>{esc(repo)}</td><td>{url_cell}</td>'
                           f'<td class="text-muted small">{esc(match)}</td></tr>')
    github_tbl = ('<table class="table table-sm w-100 dt">'
                  '<thead><tr><th>Repository / File</th><th>URL</th><th>Match</th></tr></thead>'
                  f'<tbody>{"".join(github_rows)}</tbody></table>')

    google_findings = sorted(gdorks.get("findings", []),
                             key=lambda f: (not f.get("results_found", False)))
    google_rows = []
    for f in google_findings:
        if not isinstance(f, dict):
            continue
        hit = ('<span class="text-success">yes</span>'
               if f.get("results_found") else '<span class="text-muted">no</span>')
        results = f.get("results") or []
        if results:
            tops = "<br>".join(
                f'<a href="{esc(r.get("url",""))}" target="_blank">'
                f'{esc((r.get("title") or r.get("url","") or "")[:90])}</a>'
                for r in results[:3] if isinstance(r, dict))
        else:
            tops = "<br>".join(
                f'<a href="{esc(u)}" target="_blank">{esc(str(u)[:90])}</a>'
                for u in (f.get("top_results", []) or [])[:3])
        google_rows.append(
            f'<tr><td class="small">{esc(f.get("dork",""))}</td><td>{hit}</td>'
            f'<td class="small">{tops}</td>'
            f'<td class="text-muted small">{esc(f.get("note",""))}</td></tr>')
    google_tbl = ('<table class="table table-sm w-100 dt">'
                  '<thead><tr><th>Dork</th><th>Hit</th><th>Top Results</th><th>Note</th></tr></thead>'
                  f'<tbody>{"".join(google_rows)}</tbody></table>')

    body = f"""
<ul class="nav nav-pills mb-3 flex-wrap">
  <li class="nav-item"><button class="nav-link active" data-bs-toggle="pill" data-bs-target="#exp-leakix">LeakIX ({leakix.get("count", 0)})</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#exp-github">GitHub Secrets ({gitminer.get("count", 0)})</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#exp-google">Google Dorks ({gdorks.get("count", 0)}/{gdorks.get("dorks_total", 0)})</button></li>
</ul>
<div class="tab-content">
  <div class="tab-pane fade show active" id="exp-leakix">{_section("LeakIX", leakix_tbl, "Source: leakix.net — method: <code>" + esc(leakix.get("method", "n/a")) + "</code>")}</div>
  <div class="tab-pane fade" id="exp-github">{_section("GitHub Secrets (Gitminer3)", github_tbl, "Scoped to the target domain. Verify each hit manually.")}</div>
  <div class="tab-pane fade" id="exp-google">{_section("Google Dorks (Tavily)", google_tbl, "Queries returning results are listed first.")}</div>
</div>
"""
    return page(domain, "09-exposure.html", "Exposure", body)


def _page_ip(domain: str, ip_data: dict) -> str:
    rows = []
    for r in ip_data.get("results", []):
        if not isinstance(r, dict):
            continue
        fqdns = ", ".join(r.get("fqdns", []) or [])
        valid = ('<span class="text-success">yes</span>'
                 if r.get("validated") else '<span class="text-muted">no</span>')
        rows.append(f'<tr><td>{esc(r.get("ip",""))}</td><td>{esc(fqdns)}</td>'
                    f'<td>{valid}</td><td class="small">{esc(r.get("status",""))}</td></tr>')
    note = (f'Resolved: <strong class="text-info">{ip_data.get("resolved", 0)}/'
            f'{ip_data.get("total_ips", 0)}</strong> &nbsp;|&nbsp; '
            f'FCrDNS-validated FQDNs: <strong class="text-success">'
            f'{len(ip_data.get("validated_fqdns", []))}</strong>. '
            'Validated names are folded into the Subdomains report.')
    table = ('<table class="table table-sm w-100 dt">'
             '<thead><tr><th>IP</th><th>FQDN(s)</th><th>Validated</th><th>Status</th></tr></thead>'
             f'<tbody>{"".join(rows)}</tbody></table>')
    body = _section("IP → FQDN Resolution &amp; Validation (FCrDNS)", table, note)
    return page(domain, "ip-fqdn.html", "IP→FQDN", body)


def _page_secrets(domain: str, js_data: dict) -> str:
    secrets = js_data.get("potential_secrets", [])
    rows = "\n".join(
        f'<tr><td class="text-muted small">{esc(s["file"])}</td>'
        f'<td><div class="secret-snippet">{esc(s["snippet"][:150])}</div></td></tr>'
        for s in secrets
    )
    table = ('<table class="table table-sm w-100 dt">'
             '<thead><tr><th>File</th><th>Pattern Match</th></tr></thead>'
             f'<tbody>{rows}</tbody></table>')
    body = _section("&#9888; Potential Secrets &amp; Sensitive Patterns", table,
                    "Regex-matched patterns from crawled JS/pages. Verify manually.")
    return page(domain, "secrets.html", "Secrets", body)


# ──────────────────────────────────────────────────────────────────────────────
# Index dashboard
# ──────────────────────────────────────────────────────────────────────────────

def _page_index(domain: str, sub_data, val_data, js_data, collect_data,
                cloud_data, email_data, exposure_data, ip_data, jsa_data,
                recon_data, all_tool_results) -> str:
    subs_by_tool = sub_data.get("by_tool", {})
    hosts = val_data.get("live_hosts", [])
    jsa_counts = jsa_data.get("counts", {})
    rcounts = recon_data.get("counts", {})

    cards = "".join([
        _card(len(sub_data.get("all", [])), "Subdomains"),
        _card(len(hosts), "Live Hosts"),
        _card(recon_data.get("screenshots", 0), "Screenshots"),
        _card(rcounts.get("total", 0), "Nuclei", "sev-high" if rcounts.get("high") or rcounts.get("critical") else ""),
        _card(len(js_data.get("endpoints", [])), "Endpoints"),
        _card(collect_data.get("counts", {}).get("downloaded", 0), "JS Collected"),
        _card(jsa_counts.get("findings", 0) + jsa_counts.get("dom", 0), "JS Findings"),
        _card(cloud_data.get("total", 0), "Cloud Assets"),
        _card(len(email_data.get("emails", [])), "Emails"),
        _card(len(ip_data.get("validated_fqdns", [])), "IP&rarr;FQDN"),
        _card(exposure_data.get("total", 0), "Exposures"),
        _card(len(js_data.get("potential_secrets", [])), "Secrets &#9888;"),
    ])

    # Server link (if gowitness report server was launched)
    server = recon_data.get("server", {}) or {}
    server_note = ""
    if server.get("started"):
        u = esc(server.get("url", ""))
        server_note = (f'<div class="alert alert-dark border small mb-4">'
                       f'gowitness screenshot server: '
                       f'<a href="{u}" target="_blank">{u}</a></div>')

    # Quick links to every report page
    link_cards = "".join(
        f'<div class="col-6 col-md-3"><a class="d-block stat-card p-3 text-center" '
        f'href="{fn}" style="text-decoration:none;color:var(--accent2);">{esc(label)}</a></div>'
        for fn, label in NAV if fn != "index.html"
    )

    # Tool execution table
    seen = {}
    for r in all_tool_results:
        if r["tool"] not in seen:
            seen[r["tool"]] = r
    tool_rows = "\n".join(
        f'<tr><td>{esc(r["tool"])}</td>'
        f'<td>{"skipped" if r.get("skipped") else "ok"}</td>'
        f'<td>{round(r.get("duration", 0), 1)}s</td>'
        f'<td class="small text-muted">{esc(r.get("skip_reason", ""))}</td></tr>'
        for r in seen.values()
    )
    tool_tbl = ('<table class="table table-sm w-100 dt">'
                '<thead><tr><th>Tool</th><th>Status</th><th>Duration</th><th>Note</th></tr></thead>'
                f'<tbody>{tool_rows}</tbody></table>')

    body = f"""
<div class="row g-3 mb-4">{cards}</div>
{server_note}
<div class="row g-3 mb-4">
  <div class="col-md-3"><div class="section-card p-3"><div class="section-title">Subdomain Sources</div>
    <div class="chart-container"><canvas id="chartSources"></canvas></div></div></div>
  <div class="col-md-3"><div class="section-card p-3"><div class="section-title">HTTP Status Codes</div>
    <div class="chart-container"><canvas id="chartStatus"></canvas></div></div></div>
  <div class="col-md-3"><div class="section-card p-3"><div class="section-title">Nuclei Severity</div>
    <div class="chart-container"><canvas id="chartNuclei"></canvas></div></div></div>
  <div class="col-md-3"><div class="section-card p-3"><div class="section-title">Tool Execution (s)</div>
    <div class="chart-container"><canvas id="chartTools"></canvas></div></div></div>
</div>

<div class="section-card p-3 mb-4">
  <div class="section-title">Reports</div>
  <div class="row g-2">{link_cards}</div>
</div>

{_section("Tool Execution Summary", tool_tbl)}
"""

    extra_script = f"""
  const srcData = {_chart_sources(subs_by_tool)};
  new Chart(document.getElementById('chartSources'), {{
    type: 'doughnut',
    data: {{ labels: srcData.labels, datasets: [{{ data: srcData.values,
      backgroundColor: ['#00ff88','#0dcaf0','#6f42c1','#fd7e14'], borderWidth: 0 }}] }},
    options: {{ plugins: {{ legend: {{ labels: {{ color: '#cdd9e5' }} }} }}, cutout: '65%' }}
  }});
  const stData = {_chart_status(hosts)};
  new Chart(document.getElementById('chartStatus'), {{
    type: 'bar',
    data: {{ labels: stData.labels, datasets: [{{ data: stData.values, backgroundColor: stData.colors, borderWidth: 0 }}] }},
    options: {{ plugins: {{ legend: {{ display: false }} }},
      scales: {{ x: {{ ticks: {{ color: '#8899aa' }}, grid: {{ color: '#1e2940' }} }},
                 y: {{ ticks: {{ color: '#8899aa' }}, grid: {{ color: '#1e2940' }} }} }} }}
  }});
  const nucData = {_chart_nuclei(rcounts)};
  new Chart(document.getElementById('chartNuclei'), {{
    type: 'doughnut',
    data: {{ labels: nucData.labels, datasets: [{{ data: nucData.values, backgroundColor: nucData.colors, borderWidth: 0 }}] }},
    options: {{ plugins: {{ legend: {{ labels: {{ color: '#cdd9e5' }} }} }}, cutout: '60%' }}
  }});
  const toolData = {_chart_tools(all_tool_results)};
  new Chart(document.getElementById('chartTools'), {{
    type: 'bar',
    data: {{ labels: toolData.labels, datasets: [{{ data: toolData.values, backgroundColor: toolData.colors, borderWidth: 0 }}] }},
    options: {{ indexAxis: 'y', plugins: {{ legend: {{ display: false }} }},
      scales: {{ x: {{ ticks: {{ color: '#8899aa' }}, grid: {{ color: '#1e2940' }} }},
                 y: {{ ticks: {{ color: '#8899aa' }}, grid: {{ color: '#1e2940' }} }} }} }}
  }});
"""
    return page(domain, "index.html", "Overview", body,
                with_charts=True, extra_script=extra_script)


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def generate_report(
    domain: str,
    reports_dir: Path,
    sub_data:      dict,
    val_data:      dict,
    js_data:       dict,
    collect_data:  dict,
    cloud_data:    dict,
    email_data:    dict,
    exposure_data: dict | None = None,
    ip_data:       dict | None = None,
    jsa_data:      dict | None = None,
    recon_data:    dict | None = None,
) -> Path:
    log.info("=== Stage 10: Generating HTML Reports (split per stage) ===")
    exposure_data = exposure_data or {}
    ip_data       = ip_data or {}
    jsa_data      = jsa_data or {}
    recon_data    = recon_data or {"counts": {}, "screenshots": 0, "server": {}}

    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    all_tool_results = (
        sub_data.get("tool_results", [])
        + val_data.get("tool_results", [])
        + recon_data.get("tool_results", [])
        + js_data.get("tool_results", [])
        + collect_data.get("tool_results", [])
        + jsa_data.get("tool_results", [])
        + cloud_data.get("tool_results", [])
        + email_data.get("tool_results", [])
        + exposure_data.get("tool_results", [])
        + ip_data.get("tool_results", [])
    )

    # Write each stage page. (03-nuclei.html and 06-js-analysis.html are written
    # by their own stages; here we only own the rest.)
    pages: dict[str, str] = {
        "01-subdomains.html": _page_subdomains(domain, sub_data),
        "02-live-hosts.html": _page_live_hosts(domain, val_data),
        "04-endpoints.html":  _page_endpoints(domain, js_data),
        "05-assets.html":     _page_assets(domain, collect_data),
        "07-cloud.html":      _page_cloud(domain, cloud_data),
        "08-email.html":      _page_email(domain, email_data),
        "09-exposure.html":   _page_exposure(domain, exposure_data),
        "ip-fqdn.html":       _page_ip(domain, ip_data),
        "secrets.html":       _page_secrets(domain, js_data),
        "index.html":         _page_index(
            domain, sub_data, val_data, js_data, collect_data, cloud_data,
            email_data, exposure_data, ip_data, jsa_data, recon_data,
            all_tool_results),
    }
    for filename, html in pages.items():
        (reports_dir / filename).write_text(html, encoding="utf-8")

    # 03-nuclei.html and 06-js-analysis.html are written by their own stages.
    # If those stages were skipped, drop a placeholder so nav links never 404.
    placeholders = {
        "03-nuclei.html":      ("Nuclei Vulnerability Scan",
                                 "Stage 3 (gowitness + nuclei) was not run for this scan."),
        "06-js-analysis.html": ("JS Analysis",
                                 "Stage 6 (semgrep + DOM analysis) was not run for this scan."),
    }
    for filename, (subtitle, msg) in placeholders.items():
        if not (reports_dir / filename).exists():
            body = _section(subtitle, f'<p class="text-muted">{esc(msg)}</p>')
            (reports_dir / filename).write_text(
                page(domain, filename, subtitle, body), encoding="utf-8")

    index_path = reports_dir / "index.html"
    log.info("Reports written to: %s (%d pages)", reports_dir, len(pages))
    return index_path
