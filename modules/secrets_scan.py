"""
Stage 6 (branch i) — Secrets & Intel Scanning of downloaded JavaScript

Two complementary passes over the assets collected in Stage 5
(``05-assets/collected/``):

  1. Manual catalog scan — a large set of regexes (ported from the "JS Analyzer"
     Burp extension) for high-value **secrets**, plus **endpoints**, **URLs**,
     **emails**, and sensitive **file** references, with an extensive noise-filter
     layer so the report stays signal-heavy.

  2. trufflehog — ``trufflehog filesystem <collected-dir> --json`` for
     detector-backed (optionally verified) secret detection.

Runs alongside the semgrep + DOM analysis (branch ii, ``js_analysis.py``). Results
are written to a standalone ``reports/secrets.html`` and summarised into the run.
"""
import asyncio
import json
import logging
import re
from collections import Counter, defaultdict
from pathlib import Path

from utils.htmlreport import esc, page
from utils.runner import ToolResult, run_tool

log = logging.getLogger("agente.secrets")

# ──────────────────────────────────────────────────────────────────────────────
# Pattern catalogs (ported from the JS Analyzer Burp extension)
# ──────────────────────────────────────────────────────────────────────────────

ENDPOINT_PATTERNS = [
    re.compile(r'["\']((?:https?:)?//[^"\']+/api/[a-zA-Z0-9/_-]+)["\']', re.I),
    re.compile(r'["\'](/api/v?\d*/[a-zA-Z0-9/_-]{2,})["\']', re.I),
    re.compile(r'["\'](/v\d+/[a-zA-Z0-9/_-]{2,})["\']', re.I),
    re.compile(r'["\'](/rest/[a-zA-Z0-9/_-]{2,})["\']', re.I),
    re.compile(r'["\'](/graphql[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/oauth[0-9]*/[a-zA-Z0-9/_-]+)["\']', re.I),
    re.compile(r'["\'](/auth[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/login[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/logout[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/token[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/admin[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/dashboard[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/internal[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/debug[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/config[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/backup[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/private[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/upload[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/download[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/\.well-known/[a-zA-Z0-9/_-]+)["\']', re.I),
    re.compile(r'["\'](/idp/[a-zA-Z0-9/_-]+)["\']', re.I),
]

URL_PATTERNS = [
    re.compile(r'["\'](https?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](wss?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](sftp://[^\s"\'<>]{10,})["\']'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://storage\.googleapis\.com/[^\s"\'<>]*)'),
    re.compile(r'https:\/\/[a-z0-9-]+\.firebaseio\.com'),
]

# (regex, label, high_confidence). The two bare 32-char patterns (Bugsnag /
# Datadog) match almost any minified token, so they are gated on a nearby
# keyword (see _keyword_gated) and marked low-confidence to keep the report usable.
SECRET_PATTERNS = [
    (re.compile(r'(AKIA[0-9A-Z]{16})'), "AWS Key", True),
    (re.compile(r'(AIza[0-9A-Za-z\-_]{35})'), "Google API", True),
    (re.compile(r'(sk_live_[0-9a-zA-Z]{24,})'), "Stripe Live", True),
    (re.compile(r'(ghp_[0-9a-zA-Z]{36})'), "GitHub PAT", True),
    (re.compile(r'(xox[baprs]-[0-9a-zA-Z\-]{10,48})'), "Slack Token", True),
    (re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'), "JWT", True),
    (re.compile(r'(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)'), "Private Key", True),
    (re.compile(r'(mongodb(?:\+srv)?://[^\s"\'<>]+)'), "MongoDB", True),
    (re.compile(r'(postgres(?:ql)?://[^\s"\'<>]+)'), "PostgreSQL", True),
    (re.compile(r'(?i)algolia.{0,32}([a-z0-9]{32})\b'), "Algolia Admin API Key", True),
    (re.compile(r'(?i)algolia.{0,16}([A-Z0-9]{10})\b'), "Algolia Application ID", True),
    (re.compile(r'(?i)cloudflare.{0,32}(?:secret|private|access|key|token).{0,32}([a-z0-9_-]{38,42})\b'), "Cloudflare API Token", True),
    (re.compile(r'(?i)(?:cloudflare|x-auth-user-service-key).{0,64}(v1\.0-[a-z0-9._-]{160,})\b'), "Cloudflare Service Key", True),
    (re.compile(r'(mysql:\/\/[a-z0-9._%+\-]+:[^\s:@]+@(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{2,5})?(?:\/[^\s"\'?:]+)?(?:\?[^\s"\']*)?)'), "MySQL URI with Credentials", True),
    (re.compile(r'\b(sgp_[A-Z0-9_-]{60,70})\b'), "Segment Public API Token", True),
    (re.compile(r'(?i)(?:segment|sgmt).{0,16}(?:secret|private|access|key|token).{0,16}([A-Z0-9_-]{40,50}\.[A-Z0-9_-]{40,50})'), "Segment API Key", True),
    (re.compile(r'(?i)(?:facebook|fb).{0,8}(?:app|application).{0,16}(\d{15})\b'), "Facebook App ID", True),
    (re.compile(r'(?i)(?:facebook|fb).{0,32}(?:api|app|application|client|consumer|secret|key).{0,32}([a-z0-9]{32})\b'), "Facebook Secret Key", True),
    (re.compile(r'(EAACEdEose0cBA[A-Z0-9]{20,})\b'), "Facebook Access Token", True),
    (re.compile(r'\b(ya29\.[a-z0-9_-]{30,})\b'), "Google OAuth2 Access Token", True),
    (re.compile(r'\d{9}:[a-zA-Z0-9_-]{35}'), "Telegram Bot Token", True),
    (re.compile(r'lin_api_[a-zA-Z0-9]{40}'), "Linear API Key", True),
    (re.compile(r"[hH]eroku['\"][0-9a-f]{32}['\"]"), "Heroku API Key", True),
    (re.compile(r'dop_v1_[a-z0-9]{64}'), "DigitalOcean Token", True),
    (re.compile(r'SK[0-9a-fA-F]{32}'), "Twilio API Key", True),
    (re.compile(r'SG\.[\w\d\-_]{22}\.[\w\d\-_]{43}'), "SendGrid API Key", True),
    (re.compile(r'sl\.[A-Za-z0-9_-]{20,100}'), "Dropbox Access Token", True),
    (re.compile(r'glpat-[0-9a-zA-Z-_]{20}'), "GitLab Token", True),
    (re.compile(r'shpat_[0-9a-fA-F]{32}'), "Shopify Access Token", True),
    (re.compile(r'NRII-[a-zA-Z0-9]{20,}'), "New Relic Key", True),
    # Ultra-generic — keyword-gated + low confidence to suppress hash noise.
    (re.compile(r'[a-f0-9]{32}'), "Bugsnag API Key", False),
    (re.compile(r'[a-z0-9]{32}'), "Datadog API Key", False),
]

# Labels whose generic pattern only counts when the keyword appears nearby.
_KEYWORD_GATED = {"Bugsnag API Key": "bugsnag", "Datadog API Key": "datadog"}

EMAIL_PATTERN = re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})')

FILE_PATTERNS = re.compile(
    r'["\']([a-zA-Z0-9_/.-]+\.(?:'
    r'sql|csv|xlsx|xls|json|xml|yaml|yml|'
    r'txt|log|conf|config|cfg|ini|env|'
    r'bak|backup|old|orig|copy|'
    r'key|pem|crt|cer|p12|pfx|'
    r'doc|docx|pdf|'
    r'zip|tar|gz|rar|7z|'
    r'sh|bat|ps1|py|rb|pl'
    r'))["\']',
    re.I,
)

# ── Noise filters ─────────────────────────────────────────────────────────────
NOISE_DOMAINS = {
    'www.w3.org', 'schemas.openxmlformats.org', 'schemas.microsoft.com',
    'purl.org', 'purl.oclc.org', 'openoffice.org', 'docs.oasis-open.org',
    'sheetjs.openxmlformats.org', 'ns.adobe.com', 'www.xml.org',
    'example.com', 'test.com', 'localhost', '127.0.0.1',
    'fusioncharts.com', 'jspdf.default.namespaceuri',
    'npmjs.org', 'registry.npmjs.org',
    'github.com/indutny', 'github.com/crypto-browserify',
    'jqwidgets.com', 'ag-grid.com',
}

NOISE_PATTERNS = [
    re.compile(r'^\.\.?/'),
    re.compile(r'^[a-z]{2}(-[a-z]{2})?\.js$'),
    re.compile(r'^[a-z]{2}(-[a-z]{2})?$'),
    re.compile(r'-xform$'),
    re.compile(r'^sha\d*$'),
    re.compile(r'^aes$|^des$|^md5$'),
    re.compile(r'^/[A-Z][a-z]+\s'),
    re.compile(r'^/[A-Z][a-z]+$'),
    re.compile(r'^\d+ \d+ R$'),
    re.compile(r'^xl/'),
    re.compile(r'^docProps/'),
    re.compile(r'^_rels/'),
    re.compile(r'^META-INF/'),
    re.compile(r'\.xml$'),
    re.compile(r'^worksheets/'),
    re.compile(r'^theme/'),
    re.compile(r'^webpack'),
    re.compile(r'^zone\.js$'),
    re.compile(r'^readable-stream/'),
    re.compile(r'^process/'),
    re.compile(r'^stream/'),
    re.compile(r'^buffer$'),
    re.compile(r'^events$'),
    re.compile(r'^util$'),
    re.compile(r'^path$'),
    re.compile(r'^\+'),
    re.compile(r'^\$\{'),
    re.compile(r'^#'),
    re.compile(r'^\?\ref='),
    re.compile(r'^/[a-z]$'),
    re.compile(r'^/[A-Z]$'),
    re.compile(r'^http://$'),
    re.compile(r'_ngcontent'),
]

NOISE_STRINGS = {
    'http://', 'https://', '/a', '/P', '/R', '/V', '/W',
    'zone.js', 'bn.js', 'hash.js', 'md5.js', 'sha.js', 'des.js',
    'asn1.js', 'declare.js', 'elliptic.js',
}


# ──────────────────────────────────────────────────────────────────────────────
# Validation (noise rejection)
# ──────────────────────────────────────────────────────────────────────────────

def _is_valid_endpoint(value: str) -> bool:
    if not value or len(value) < 3 or value in NOISE_STRINGS:
        return False
    if any(p.search(value) for p in NOISE_PATTERNS):
        return False
    if not value.startswith('/'):
        return False
    parts = value.split('/')
    if len(parts) < 2 or all(len(p) < 2 for p in parts if p):
        return False
    return True


def _is_valid_url(value: str) -> bool:
    if not value or len(value) < 15:
        return False
    low = value.lower()
    if any(d in low for d in NOISE_DOMAINS):
        return False
    if '{' in value or 'undefined' in low or 'null' in low:
        return False
    if low.startswith('data:'):
        return False
    if any(low.endswith(ext) for ext in ('.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf')):
        return False
    return True


def _is_valid_secret(value: str) -> bool:
    if not value or len(value) < 10:
        return False
    low = value.lower()
    if any(x in low for x in ('example', 'placeholder', 'your', 'xxxx', 'test')):
        return False
    return True


def _is_valid_email(value: str) -> bool:
    if not value or '@' not in value:
        return False
    low = value.lower()
    domain = value.split('@')[-1].lower()
    if domain in {'example.com', 'test.com', 'domain.com', 'placeholder.com'}:
        return False
    if any(x in low for x in ('example', 'test', 'placeholder', 'noreply')):
        return False
    return True


def _is_valid_file(value: str) -> bool:
    if not value or len(value) < 3:
        return False
    low = value.lower()
    if any(x in low for x in (
            'package.json', 'tsconfig.json', 'webpack', 'babel', 'eslint',
            'prettier', 'node_modules', '.min.', 'polyfill', 'vendor',
            'chunk', 'bundle')):
        return False
    if low.endswith('.map'):
        return False
    if low.endswith('.json') and len(value.split('/')[-1]) <= 7:
        return False
    return True


def _mask(value: str) -> str:
    return value[:10] + "..." + value[-4:] if len(value) > 20 else value


def _keyword_gated(label: str, text: str, start: int) -> bool:
    """For ultra-generic patterns, require the vendor keyword within 40 chars."""
    kw = _KEYWORD_GATED.get(label)
    if not kw:
        return True
    ctx = text[max(0, start - 40):start + 40].lower()
    return kw in ctx


# ──────────────────────────────────────────────────────────────────────────────
# Manual catalog scan over collected files
# ──────────────────────────────────────────────────────────────────────────────

_TEXT_EXTS = {".js", ".json", ".config", ".map", ".txt", ".ts", ".jsx", ".tsx",
              ".html", ".css", ".env", ".yml", ".yaml"}


def _iter_text_files(root: Path, max_bytes: int):
    for f in root.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() not in _TEXT_EXTS:
            continue
        try:
            if f.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        yield f


def _scan_manual(root: Path, cfg: dict) -> dict:
    max_bytes = int(cfg.get("max_file_mb", 5)) * 1024 * 1024
    findings = {"secrets": [], "endpoints": [], "urls": [], "emails": [], "files": []}
    seen: set[str] = set()

    def add(cat: str, value: str, rel: str, extra: dict | None = None) -> None:
        key = f"{cat}:{value}"
        if key in seen:
            return
        seen.add(key)
        item = {"value": value, "source": rel}
        if extra:
            item.update(extra)
        findings[cat].append(item)

    for f in _iter_text_files(root, max_bytes):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        rel = str(f.relative_to(root))

        for pattern in ENDPOINT_PATTERNS:
            for m in pattern.finditer(text):
                v = m.group(1).strip()
                if _is_valid_endpoint(v):
                    add("endpoints", v, rel)

        for pattern in URL_PATTERNS:
            for m in pattern.finditer(text):
                v = (m.group(1) if m.lastindex else m.group(0)).strip()
                if _is_valid_url(v):
                    add("urls", v, rel)

        for pattern, label, high in SECRET_PATTERNS:
            for m in pattern.finditer(text):
                v = (m.group(1) if m.lastindex else m.group(0)).strip()
                if not _is_valid_secret(v):
                    continue
                if not _keyword_gated(label, text, m.start()):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                add("secrets", v, rel,
                    {"type": label, "confidence": "high" if high else "low",
                     "masked": _mask(v), "line": line})

        for m in EMAIL_PATTERN.finditer(text):
            v = m.group(1).strip()
            if _is_valid_email(v):
                add("emails", v, rel)

        for m in FILE_PATTERNS.finditer(text):
            v = m.group(1).strip()
            if _is_valid_file(v):
                add("files", v, rel)

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# trufflehog
# ──────────────────────────────────────────────────────────────────────────────

async def _run_trufflehog(root: Path, stage_dir: Path, cfg: dict) -> tuple[list[dict], ToolResult | None]:
    if not cfg.get("enabled", True):
        return [], None
    cmd = ["trufflehog", "filesystem", str(root), "--json", "--no-update"]
    if not cfg.get("verify", False):
        cmd.append("--no-verification")
    cmd += cfg.get("extra_args", [])
    result = await run_tool(cmd, "trufflehog", timeout=cfg.get("timeout"))

    # trufflehog emits one JSON object per line on stdout.
    (stage_dir / "trufflehog.jsonl").write_text(result.stdout or "", encoding="utf-8")
    hits: list[dict] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        meta = (((obj.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
        raw = obj.get("Raw") or obj.get("Redacted") or ""
        hits.append({
            "detector": obj.get("DetectorName", "?"),
            "verified": bool(obj.get("Verified", False)),
            "file": meta.get("file", ""),
            "line": meta.get("line", ""),
            "redacted": _mask(str(raw)) if raw else (obj.get("Redacted") or ""),
        })
    return hits, result


# ──────────────────────────────────────────────────────────────────────────────
# HTML report (owns reports/secrets.html)
# ──────────────────────────────────────────────────────────────────────────────

def _card(value, label, cls="") -> str:
    return (f'<div class="col-6 col-md-2"><div class="stat-card p-3 text-center">'
            f'<div class="stat-value {cls}">{value}</div>'
            f'<div class="stat-label">{label}</div></div></div>')


def _simple_table(rows_html: str, headers: list[str]) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    return (f'<table class="table table-sm w-100 dt"><thead><tr>{head}</tr></thead>'
            f'<tbody>{rows_html}</tbody></table>')


def _th_row(h: dict) -> str:
    verified = ('<span class="sev-critical">yes</span>' if h["verified"]
                else '<span class="text-muted">no</span>')
    return ('<tr>'
            f'<td>{esc(h["detector"])}</td><td>{verified}</td>'
            f'<td class="small text-muted">{esc(h["file"])}</td><td>{esc(h["line"])}</td>'
            f'<td><span class="secret-snippet">{esc(h["redacted"])}</span></td></tr>')


def _sec_row(s: dict) -> str:
    conf = s.get("confidence", "")
    conf_cls = "sev-high" if conf == "high" else "sev-low"
    order = 0 if conf == "high" else 1
    return (f'<tr data-order="{order}">'
            f'<td>{esc(s.get("type", ""))}</td>'
            f'<td class="{conf_cls}">{esc(conf)}</td>'
            f'<td class="small text-muted">{esc(s["source"])}</td>'
            f'<td>{esc(s.get("line", ""))}</td>'
            f'<td><span class="secret-snippet">{esc(s.get("masked", s["value"]))}</span></td></tr>')


def _build_report(domain: str, data: dict, report_path: Path) -> None:
    manual = data["manual"]
    th = data["trufflehog"]
    c = data["counts"]

    cards = "".join([
        _card(c["secrets"], "Regex Secrets", "sev-high" if c["secrets"] else ""),
        _card(c["trufflehog"], "TruffleHog", "sev-high" if c["trufflehog"] else ""),
        _card(c["trufflehog_verified"], "Verified &#9888;", "sev-critical" if c["trufflehog_verified"] else ""),
        _card(c["endpoints"], "Endpoints"),
        _card(c["urls"], "URLs"),
        _card(c["emails"], "Emails"),
        _card(c["files"], "File Refs"),
    ])

    th_rows = "\n".join(_th_row(h) for h in
                        sorted(th, key=lambda x: (not x["verified"], x["detector"])))
    sec_rows = "\n".join(_sec_row(s) for s in
                         sorted(manual["secrets"],
                                key=lambda x: (x.get("confidence") != "high", x.get("type", ""))))

    def intel_rows(items):
        return "\n".join(
            f'<tr><td>{esc(i["value"])}</td><td class="small text-muted">{esc(i["source"])}</td></tr>'
            for i in items)

    body = f"""
<div class="row g-3 mb-4">{cards}</div>
<p class="text-muted small">Scanned the JavaScript/JSON/config downloaded in Stage 5.
Secret values are masked. Low-confidence regex hits (generic 32-char tokens) are
keyword-gated to reduce noise — still verify every finding manually.</p>

<ul class="nav nav-pills mb-3 flex-wrap">
  <li class="nav-item"><button class="nav-link active" data-bs-toggle="pill" data-bs-target="#s-th">TruffleHog ({c['trufflehog']})</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#s-sec">Regex Secrets ({c['secrets']})</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#s-ep">Endpoints ({c['endpoints']})</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#s-url">URLs ({c['urls']})</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#s-em">Emails ({c['emails']})</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#s-file">File Refs ({c['files']})</button></li>
</ul>
<div class="tab-content">
  <div class="tab-pane fade show active" id="s-th"><div class="section-card p-3">
    <div class="section-title">TruffleHog Findings</div>
    {_simple_table(th_rows, ["Detector", "Verified", "File", "Line", "Secret (masked)"])}</div></div>
  <div class="tab-pane fade" id="s-sec"><div class="section-card p-3">
    <div class="section-title">Regex Catalog Secrets</div>
    {_simple_table(sec_rows, ["Type", "Confidence", "File", "Line", "Secret (masked)"])}</div></div>
  <div class="tab-pane fade" id="s-ep"><div class="section-card p-3">
    <div class="section-title">Endpoints in JS</div>
    {_simple_table(intel_rows(manual['endpoints']), ["Endpoint", "Source File"])}</div></div>
  <div class="tab-pane fade" id="s-url"><div class="section-card p-3">
    <div class="section-title">URLs in JS</div>
    {_simple_table(intel_rows(manual['urls']), ["URL", "Source File"])}</div></div>
  <div class="tab-pane fade" id="s-em"><div class="section-card p-3">
    <div class="section-title">Emails in JS</div>
    {_simple_table(intel_rows(manual['emails']), ["Email", "Source File"])}</div></div>
  <div class="tab-pane fade" id="s-file"><div class="section-card p-3">
    <div class="section-title">Sensitive File References</div>
    {_simple_table(intel_rows(manual['files']), ["File Reference", "Source File"])}</div></div>
</div>
"""
    # Tables in inactive tabs need explicit init.
    dt_init = "\n".join(
        f"  $('#{i} table.dt').each(function(){{ if(!$.fn.dataTable.isDataTable(this)) $(this).DataTable(dtOpts); }});"
        for i in ("s-th", "s-sec", "s-ep", "s-url", "s-em", "s-file"))
    html = page(domain, "secrets.html", "Secrets & JS Intel", body, extra_script=dt_init)
    report_path.write_text(html, encoding="utf-8")
    log.info("Secrets report -> %s", report_path)


# ──────────────────────────────────────────────────────────────────────────────
# Stage entry point
# ──────────────────────────────────────────────────────────────────────────────

def _empty(report_file: str = "", skip_reason: str = "") -> dict:
    return {
        "manual": {"secrets": [], "endpoints": [], "urls": [], "emails": [], "files": []},
        "trufflehog": [],
        "counts": {"secrets": 0, "trufflehog": 0, "trufflehog_verified": 0,
                   "endpoints": 0, "urls": 0, "emails": 0, "files": 0, "total": 0},
        "report_file": report_file, "skipped": True, "skip_reason": skip_reason,
        "tool_results": [],
    }


async def _noop_manual() -> dict:
    return {"secrets": [], "endpoints": [], "urls": [], "emails": [], "files": []}


async def scan_secrets(domain: str, stage_dir: Path, reports_dir: Path, cfg: dict,
                       collect_data: dict) -> dict:
    log.info("=== Stage 6 (i): Secrets & JS Intel Scanning ===")
    scfg = cfg.get("secrets", {})
    report_path = reports_dir / "secrets.html"

    if not scfg.get("enabled", True):
        log.info("Secrets scan: disabled in config — skipping")
        data = _empty(str(report_path), "disabled in config")
        _build_report(domain, data, report_path)
        return data

    root = Path(collect_data.get("root") or "")
    if not root or not root.exists():
        log.warning("Secrets scan: collected directory not found: %s", root)
        data = _empty(str(report_path), f"collected directory not found: {root}")
        _build_report(domain, data, report_path)
        return data

    # Manual catalog scan (CPU-bound → thread) + trufflehog (subprocess) together.
    manual_cfg = scfg.get("manual_scan", {})
    th_cfg = scfg.get("trufflehog", {})
    manual_task = (asyncio.to_thread(_scan_manual, root, manual_cfg)
                   if manual_cfg.get("enabled", True) else _noop_manual())
    th_hits, th_result = await _run_trufflehog(root, stage_dir, th_cfg)
    manual = await manual_task

    counts = {
        "secrets": len(manual["secrets"]),
        "trufflehog": len(th_hits),
        "trufflehog_verified": sum(1 for h in th_hits if h["verified"]),
        "endpoints": len(manual["endpoints"]),
        "urls": len(manual["urls"]),
        "emails": len(manual["emails"]),
        "files": len(manual["files"]),
    }
    counts["total"] = counts["secrets"] + counts["trufflehog"]

    data = {
        "manual": manual, "trufflehog": th_hits, "counts": counts,
        "report_file": str(report_path), "skipped": False, "skip_reason": "",
        "tool_results": ([{"tool": th_result.tool, "duration": th_result.duration,
                           "skipped": th_result.skipped, "skip_reason": th_result.skip_reason}]
                         if th_result else []),
    }

    # Persist a machine-readable copy alongside the raw trufflehog output.
    (stage_dir / "secrets_findings.json").write_text(
        json.dumps({"counts": counts, "manual": manual, "trufflehog": th_hits}, indent=2),
        encoding="utf-8")

    _build_report(domain, data, report_path)
    log.info("Secrets: regex=%d trufflehog=%d (verified=%d) | endpoints=%d urls=%d emails=%d files=%d",
             counts["secrets"], counts["trufflehog"], counts["trufflehog_verified"],
             counts["endpoints"], counts["urls"], counts["emails"], counts["files"])
    return data
