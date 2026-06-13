"""
Stage 7 — Exposure & Secrets Discovery (external OSINT)

Three independent components, all scoped to the target organization:

  1. LeakIX     — query leakix.net for known leaks/exposures affecting the
                  domain. Primary method drives Chrome via Claude Code so the
                  rendered result list is captured; falls back to the LeakIX
                  JSON API (requests) when the `claude` CLI is unavailable.

  2. Gitminer3  — GitHub secret/dork mining (unkl4b/Gitminer3). A dorks.txt is
                  generated from a curated credential-leak dork list with the
                  target domain appended to every line so searches stay in scope.

  3. Google     — orchestrates Claude Code + Chrome to run a curated set of
     Dorks        Google dorks (substituting the target domain/company), records
                  which return hits, and folds the findings into the HTML report.

Everything is best-effort: missing tools, a missing `claude` CLI, or a
rate-limited search degrade to "skipped" rather than failing the pipeline.
The generated dork files are always written so an operator can run them by hand.

Authorized use only — run against domains you have explicit permission to test.
"""
import asyncio
import csv
import logging
import os
import urllib.parse
import urllib.request
from pathlib import Path

from utils.runner import ToolResult, run_tool
from utils import claude_browser

log = logging.getLogger("agente.exposure")

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


# ──────────────────────────────────────────────────────────────────────────────
# Dork corpora
# ──────────────────────────────────────────────────────────────────────────────

# Credential / secret-leak dorks for Gitminer3 (GitHub code search). The target
# domain is appended to every line at runtime to scope results to the org.
_GITMINER_DORKS = """\
filename:.env DB_PASSWORD
filename:.env SECRET_KEY
filename:.env API_KEY
filename:.env ACCESS_TOKEN
filename:.env CLIENT_SECRET
filename:.env PRIVATE_KEY
filename:.env password
filename:.env token
filename:.env auth
filename:.env.local password
filename:.env.production password
filename:.env.staging password
filename:.env.backup password
filename:credentials password
filename:secrets.yml password
filename:secrets.yaml password
filename:secrets.json password
filename:.netrc password
filename:.npmrc _auth
filename:.pypirc password
filename:.git-credentials password
extension:pem private
extension:pem PRIVATE KEY
extension:ppk private
extension:ppk PuTTY
extension:p12 password
extension:pfx password
extension:key private
filename:id_rsa PRIVATE KEY
filename:id_dsa PRIVATE KEY
filename:id_ecdsa PRIVATE KEY
filename:id_ed25519 PRIVATE KEY
filename:keystore.jks password
filename:server.key BEGIN
filename:client.key BEGIN
"-----BEGIN RSA PRIVATE KEY-----"
"-----BEGIN OPENSSH PRIVATE KEY-----"
"-----BEGIN EC PRIVATE KEY-----"
"-----BEGIN DSA PRIVATE KEY-----"
"-----BEGIN PGP PRIVATE KEY BLOCK-----"
filename:.env AWS_SECRET_ACCESS_KEY
filename:.env AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY AKIA
AWS_ACCESS_KEY_ID AKIA
filename:credentials aws_access_key_id
filename:config aws_secret_access_key
AZURE_CLIENT_SECRET tenant_id
AZURE_CLIENT_ID AZURE_CLIENT_SECRET
GOOGLE_APPLICATION_CREDENTIALS private_key
filename:service-account.json private_key_id
filename:gcloud.json private_key
filename:.boto aws_access_key_id
filename:config DO_ACCESS_TOKEN
DIGITALOCEAN_ACCESS_TOKEN api
LINODE_ACCESS_TOKEN api
CLOUDFLARE_API_TOKEN api
CLOUDFLARE_API_KEY email
filename:.env HEROKU_API_KEY
filename:Procfile SECRET
filename:.env DATABASE_URL
filename:.env MONGO_URI
filename:.env REDIS_URL
filename:database.yml password
filename:database.php password
filename:db.php password
filename:config.php DB_PASSWORD
filename:wp-config.php DB_PASSWORD
filename:wp-config.php DB_USER
filename:settings.py DATABASES
filename:settings.py SECRET_KEY
filename:application.properties spring.datasource.password
filename:application.yml spring.datasource.password
filename:hibernate.cfg.xml connection.password
filename:persistence.xml password
filename:appsettings.json ConnectionStrings
filename:web.config connectionString
filename:config.yml database password
"mongodb+srv://" password
"mysql://" password
"postgres://" password
"redis://" password
"jdbc:mysql" password
"jdbc:postgresql" password
"jdbc:oracle" password
filename:.env SLACK_TOKEN
filename:.env SLACK_WEBHOOK_URL
filename:.env STRIPE_SECRET_KEY
filename:.env STRIPE_PUBLISHABLE_KEY
filename:.env TWILIO_AUTH_TOKEN
filename:.env TWILIO_ACCOUNT_SID
filename:.env SENDGRID_API_KEY
filename:.env MAILGUN_API_KEY
filename:.env MAILGUN_DOMAIN
filename:.env FIREBASE_API_KEY
filename:.env FIREBASE_PRIVATE_KEY
filename:google-services.json api_key
filename:.env OPENAI_API_KEY
filename:.env ANTHROPIC_API_KEY
filename:.env DATADOG_API_KEY
filename:.env DATADOG_APP_KEY
filename:.env PAGERDUTY_TOKEN
filename:.env JIRA_API_TOKEN
filename:.env OKTA_API_TOKEN
filename:.env OKTA_CLIENT_SECRET
filename:.env GITHUB_TOKEN
filename:.env GITLAB_TOKEN
filename:.env BITBUCKET_PASSWORD
filename:.env SALESFORCE_PASSWORD
filename:.env HUBSPOT_API_KEY
filename:.env ZENDESK_API_TOKEN
filename:.env AMPLITUDE_API_KEY
filename:.env SEGMENT_WRITE_KEY
filename:.env MIXPANEL_TOKEN
filename:.env SENTRY_DSN
filename:.env NEW_RELIC_LICENSE_KEY
filename:.env GRAFANA_API_KEY
filename:.env ELASTIC_APM_SECRET_TOKEN
filename:.env VAULT_TOKEN
filename:.env NPM_TOKEN
filename:.env DOCKERHUB_PASSWORD
filename:.env PYPI_PASSWORD
filename:.travis.yml env global
filename:.travis.yml password
filename:.travis.yml secret
filename:circle.yml aws_access_key_id
filename:.circleci/config.yml password
filename:Jenkinsfile credentials
filename:Jenkinsfile withCredentials
filename:Jenkinsfile secret
filename:.github/workflows password
filename:.github/workflows secret
filename:.drone.yml password
filename:.drone.yml secret
filename:bitbucket-pipelines.yml password
filename:azure-pipelines.yml secret
filename:Makefile password
filename:Makefile token
filename:Dockerfile ENV password
filename:Dockerfile ARG password
filename:docker-compose.yml password
filename:docker-compose.yml MYSQL_ROOT_PASSWORD
filename:docker-compose.yml POSTGRES_PASSWORD
filename:*.tfvars password
filename:terraform.tfvars secret
filename:*.tfvars access_key
filename:variables.tf default password
filename:ansible.cfg private_key_file
filename:playbook.yml become_pass
filename:inventory password
filename:vault.yml ansible_become_pass
filename:Vagrantfile password
filename:Capfile password
filename:config.py SECRET_KEY
filename:local_settings.py SECRET_KEY
filename:local_settings.py DATABASES
filename:settings/local.py SECRET_KEY
filename:settings/production.py SECRET_KEY
filename:config/database.yml password
filename:config/secrets.yml production
filename:config/initializers/secret_token.rb secret_token
filename:config/initializers/devise.rb secret_key
filename:config.js apiKey
filename:config.js secret
filename:.htpasswd password
filename:.htaccess password
filename:php.ini mysql.password
filename:parameters.yml database_password
filename:parameters.yml secret
filename:app.yaml env_variables
filename:runtime.txt python
filename:Gemfile.lock github
extension:sql password
extension:sql INSERT INTO users
extension:sql dump
extension:bak password
extension:dump password
extension:sqlite password
extension:db password
filename:*.sql DROP TABLE
filename:dump.sql user password
filename:backup.sql admin
filename:hosts ansible_ssh_pass
filename:inventory ansible_password
filename:.env INTERNAL_API_URL
filename:.env ADMIN_URL
filename:.env INTRANET_URL
filename:config.yml internal
filename:config.json internal_host
filename:.env SMTP_PASSWORD
filename:.env MAIL_PASSWORD
filename:.env EMAIL_HOST_PASSWORD
filename:config ldap_password
filename:config ldap_bind_password
filename:.env LDAP_BIND_PASSWORD
filename:.env AD_PASSWORD
"""

# Google dorks. `{domain}` and `{company}` are substituted at runtime. Non-dork
# category headings are filtered out automatically (see _build_google_dorks).
_GOOGLE_DORKS = """\
site:github.com "{company}" "aws_access_key_id"
site:github.com "{company}" "aws_secret_access_key"
site:github.com "{company}" "SECRET_KEY"
site:github.com "{company}" "client_secret"
site:github.com "{company}" "api_key"
site:github.com "{company}" "private_key"
site:github.com "{company}" "BEGIN RSA PRIVATE KEY"
site:github.com "{company}" filename:.env
site:github.com "{company}" filename:credentials
site:github.com "{company}" "password"
site:gitlab.com "{company}" "token"
site:bitbucket.org "{company}" "password"
site:{domain} intitle:"index of" "/.git"
site:{domain} intitle:"index of" /backup
site:{domain} intitle:"index of" /config
site:{domain} intitle:"index of" /uploads
site:{domain} intitle:"index of" intext:"database.sql"
site:{domain} intitle:"index of" intext:"config.yml"
site:{domain} intitle:"index of" intext:"access.log"
site:{domain} inurl:"/wp-config.php"
site:{domain} inurl:"phpinfo.php"
site:{domain} intitle:"server-status"
site:{domain} inurl:"/.env"
site:{domain} inurl:"/config.json"
site:{domain} ext:env
site:{domain} ext:log
site:{domain} ext:bak | ext:backup | ext:old
site:{domain} ext:sql | ext:db
site:{domain} ext:conf | ext:cnf | ext:ini
site:{domain} ext:git | ext:svn
site:{domain} ext:htpasswd | ext:htaccess
site:{domain} inurl:admin
site:{domain} inurl:login
site:{domain} inurl:signin
site:{domain} intitle:login
site:{domain} inurl:"/administrator"
site:{domain} inurl:"/wp-admin"
site:{domain} inurl:"/cpanel"
site:{domain} inurl:"/phpmyadmin"
site:{domain} intitle:"swagger ui"
site:{domain} inurl:swagger
site:{domain} inurl:api-docs
site:{domain} inurl:openapi.json
site:{domain} inurl:swagger.json
site:{domain} inurl:/graphql
site:{domain} inurl:redoc
site:{domain} inurl:/api/v1
site:{domain} inurl:/api/v2
site:{domain} inurl:dev
site:{domain} inurl:test
site:{domain} inurl:staging
site:{domain} inurl:uat
site:{domain} inurl:sandbox
site:{domain} inurl:debug
site:{domain} inurl:internal
site:{domain} inurl:beta
site:s3.amazonaws.com "{domain}"
site:blob.core.windows.net "{domain}"
site:storage.googleapis.com "{domain}"
site:digitaloceanspaces.com "{domain}"
site:firebaseio.com "{domain}"
site:dev.azure.com "{domain}"
site:jfrog.io "{domain}"
site:drive.google.com "{domain}"
site:docs.google.com "{domain}"
site:sharepoint.com "{domain}"
site:onedrive.live.com "{domain}"
site:dropbox.com/s "{domain}"
site:trello.com "{domain}"
site:atlassian.net "{domain}"
site:{domain} inurl:id=
site:{domain} inurl:pid=
site:{domain} inurl:cat=
site:{domain} inurl:category=
site:{domain} inurl:sid=
site:{domain} inurl:item=
site:{domain} inurl:product=
site:{domain} inurl:url=
site:{domain} inurl:path=
site:{domain} inurl:dest=
site:{domain} inurl:domain=
site:{domain} inurl:fetch=
site:{domain} inurl:proxy=
site:{domain} inurl:callback=
site:{domain} inurl:redirect=
site:{domain} inurl:redir=
site:{domain} inurl:return=
site:{domain} inurl:returnUrl=
site:{domain} inurl:next=
site:{domain} inurl:goto=
site:{domain} inurl:target=
site:{domain} inurl:file=
site:{domain} inurl:include=
site:{domain} inurl:page=
site:{domain} inurl:doc=
site:{domain} inurl:folder=
site:{domain} inurl:template=
site:{domain} inurl:cmd=
site:{domain} inurl:exec=
site:{domain} inurl:run=
site:{domain} inurl:code=
site:{domain} inurl:ping=
site:{domain} inurl:query=
site:{domain} inurl:q=
site:{domain} inurl:search=
site:{domain} inurl:keyword=
site:{domain} inurl:lang=
site:{domain} inurl:s=
site:{domain} intext:"choose file"
site:{domain} intext:"upload file"
site:{domain} inurl:upload
site:{domain} inurl:"/fileupload"
site:{domain} "SQL syntax"
site:{domain} "unhandled exception"
site:{domain} "stack trace"
site:{domain} "fatal error"
site:{domain} "undefined index"
site:{domain} intitle:"500 internal server error"
site:{domain} intitle:"exception"
site:{domain} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx intext:"confidential"
site:{domain} ext:pdf | ext:doc | ext:docx intext:"internal use only"
site:{domain} ext:pdf | ext:doc | ext:docx intext:"do not distribute"
site:{domain} ext:pdf | ext:doc | ext:docx intext:"proprietary"
site:pastebin.com "{domain}"
site:jsfiddle.net "{domain}"
site:codepen.io "{domain}"
site:gist.github.com "{domain}"
site:codebeautify.org "{domain}"
site:openbugbounty.org inurl:reports intext:"{domain}"
site:hackerone.com "{company}"
site:bugcrowd.com "{company}"
site:{domain} inurl:/security.txt intext:"bounty"
site:{domain} inurl:"/wp-content/uploads"
site:{domain} inurl:"/wp-content/plugins"
site:{domain} inurl:"/wp-json/wp/v2/users"
site:{domain} inurl:"/wp-includes" filetype:php
site:{domain} inurl:/content/usergenerated
site:{domain} inurl:/content/dam
site:{domain} inurl:/jcr:content
site:{domain} inurl:/libs/granite
site:{domain} inurl:/etc/clientlibs
site:{domain} inurl:/bin/wcm
site:{domain} inurl:/crx/de
"""

_DORK_TOKENS = ("site:", "inurl:", "intitle:", "intext:", "ext:",
                "filetype:", "filename:", "extension:")


# ──────────────────────────────────────────────────────────────────────────────
# Dork file generation
# ──────────────────────────────────────────────────────────────────────────────

def _build_gitminer_dorks(domain: str) -> list[str]:
    """Curated credential dorks with the target domain appended to each line."""
    dorks = []
    for line in _GITMINER_DORKS.splitlines():
        line = line.strip()
        if line:
            dorks.append(f"{line} {domain}")
    return dorks


def _build_google_dorks(domain: str, company: str) -> list[str]:
    """Substitute domain/company placeholders; drop category-heading lines."""
    dorks = []
    for line in _GOOGLE_DORKS.splitlines():
        line = line.strip()
        if not line or not any(tok in line for tok in _DORK_TOKENS):
            continue
        dork = line.replace("{domain}", domain).replace("{company}", company)
        dorks.append(dork)
    return dorks


# ──────────────────────────────────────────────────────────────────────────────
# 1. LeakIX
# ──────────────────────────────────────────────────────────────────────────────

def _leakix_url(domain: str) -> str:
    return f"https://leakix.net/search?scope=leak&q={urllib.parse.quote(domain)}"


def _leakix_api_key(cfg: dict) -> str:
    """API key from config, else the LEAKIX_API_KEY environment variable."""
    return cfg.get("api_key", "") or os.environ.get("LEAKIX_API_KEY", "")


def _leakix_via_api(domain: str, outdir: Path, cfg: dict) -> dict:
    """Query the LeakIX JSON API directly (Accept: application/json)."""
    if not _REQUESTS_AVAILABLE:
        return {"results": [], "count": 0, "method": "api", "skipped": True,
                "skip_reason": "requests not installed"}

    api_key = _leakix_api_key(cfg)
    if not api_key:
        log.warning("LeakIX: no API key (set exposure.leakix.api_key or the "
                    "LEAKIX_API_KEY env var) — the API requires authentication")

    url = _leakix_url(domain)
    headers = {"Accept": "application/json", "User-Agent": "AgentE-Recon/1.0"}
    if api_key:
        headers["api-key"] = api_key

    try:
        resp = requests.get(url, headers=headers, timeout=int(cfg.get("timeout", 60)))
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        log.warning("LeakIX (api) failed: %s", exc)
        return {"results": [], "count": 0, "method": "api", "skipped": True,
                "skip_reason": str(exc)[:200]}

    items = data if isinstance(data, list) else data.get("results", [])
    results = _normalize_leakix(items)
    (outdir / "leakix.json").write_text(resp.text, encoding="utf-8")
    log.info("LeakIX (api): %d result(s)", len(results))
    return {"results": results, "count": len(results), "method": "api",
            "skipped": False, "skip_reason": ""}


def _normalize_leakix(items: list) -> list[dict]:
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        out.append({
            "host":    str(it.get("host") or it.get("subdomain") or it.get("domain") or ""),
            "ip":      str(it.get("ip") or it.get("ip_address") or ""),
            "event":   str(it.get("event") or it.get("event_type")
                           or it.get("plugin") or it.get("event_source") or ""),
            "summary": str(it.get("summary") or it.get("description") or "")[:300],
            "date":    str(it.get("date") or it.get("time") or it.get("created_at") or ""),
        })
    return out


async def _run_leakix(domain: str, outdir: Path, cfg: dict) -> dict:
    log.info("LeakIX: querying leaks for %s via API", domain)
    return await asyncio.to_thread(_leakix_via_api, domain, outdir, cfg)


# ──────────────────────────────────────────────────────────────────────────────
# 2. Gitminer3
# ──────────────────────────────────────────────────────────────────────────────

async def _run_gitminer(domain: str, outdir: Path, cfg: dict, dorks_file: Path) -> dict:
    gm_dir = outdir / "gitminer"
    gm_dir.mkdir(exist_ok=True)
    csv_name = "downloaded_files.csv"

    cmd = [
        "gitminer3",
        "-d", str(dorks_file),
        "-m", str(cfg.get("max_results", 100)),
        "-o", csv_name,
        "--report",
    ]
    token = cfg.get("github_token", "") or os.environ.get("GITHUB_TOKEN", "")
    if cfg.get("github_token"):
        cmd += ["-t", cfg["github_token"]]

    env = dict(os.environ)
    if token:
        env["GITHUB_TOKEN"] = token

    result: ToolResult = await run_tool(
        cmd, "gitminer3", cwd=gm_dir, env=env,
        timeout=int(cfg.get("timeout", 1200)),
    )

    findings: list[dict] = []
    csv_path = gm_dir / csv_name
    if csv_path.exists():
        try:
            with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
                for row in csv.DictReader(fh):
                    findings.append(row)
        except Exception as exc:
            log.warning("Gitminer3: failed to parse CSV: %s", exc)

    report_md = next((p.name for p in gm_dir.glob("*.md")), "")

    if result.skipped:
        log.warning("Gitminer3: skipped (%s)", result.skip_reason)
    elif token == "":
        log.warning("Gitminer3: ran without a GitHub token — results may be empty "
                    "(set exposure.gitminer.github_token or GITHUB_TOKEN)")

    log.info("Gitminer3: %d finding(s) from %d dork(s)",
             len(findings), sum(1 for _ in dorks_file.read_text(errors='replace').splitlines() if _.strip()))

    return {
        "findings": findings,
        "count": len(findings),
        "csv_file": str(csv_path) if csv_path.exists() else "",
        "report_file": str(gm_dir / report_md) if report_md else "",
        "dorks_file": str(dorks_file),
        "skipped": result.skipped,
        "skip_reason": result.skip_reason,
        "tool_result": result,
    }


# ──────────────────────────────────────────────────────────────────────────────
# 3. Google dorks via Claude + Chrome
# ──────────────────────────────────────────────────────────────────────────────

def _google_dorks_blocking(dorks: list[str], outdir: Path, cfg: dict) -> dict:
    if not cfg.get("enabled", True):
        return {"findings": [], "count": 0, "dorks_run": 0,
                "skipped": True, "skip_reason": "disabled in config"}
    if not claude_browser.claude_available():
        log.warning("Google dorks: claude CLI not found — skipping "
                    "(full dork list still written to google_dorks.txt)")
        return {"findings": [], "count": 0, "dorks_run": 0,
                "skipped": True, "skip_reason": "claude CLI not found"}

    max_dorks  = int(cfg.get("max_dorks", 20))
    batch_size = max(1, int(cfg.get("batch_size", 5)))
    subset     = dorks[:max_dorks] if max_dorks > 0 else dorks

    findings: list[dict] = []
    run_count = 0
    for start in range(0, len(subset), batch_size):
        batch = subset[start:start + batch_size]
        numbered = "\n".join(f"{i+1}. {d}" for i, d in enumerate(batch))
        prompt = (
            "You are assisting an AUTHORIZED security assessment. For each Google "
            "search query below, open "
            "https://www.google.com/search?q=<URL-encoded query> in Chrome, let "
            "the page load, and record: whether any results were returned, the top "
            "up-to-3 result URLs, and a one-line note on anything sensitive "
            "(exposed files, admin panels, secrets, error leaks, etc.). If Google "
            "presents a CAPTCHA or blocks the search, set note to 'captcha' for "
            "that query and continue to the next. Return ONLY a JSON array, one "
            "object per query, with keys: dork (string), results_found (boolean), "
            "top_results (array of strings), note (string).\n\nQueries:\n"
            + numbered
        )
        try:
            envelope = claude_browser.run_claude_browser_task(
                prompt,
                cwd=str(outdir),
                permission_mode=cfg.get("permission_mode", "acceptEdits"),
                timeout=int(cfg.get("timeout", 600)),
                max_turns=cfg.get("max_turns"),
                max_budget_usd=cfg.get("max_budget_usd"),
            )
        except Exception as exc:
            log.warning("Google dorks: batch %d failed: %s", start // batch_size + 1, exc)
            continue

        run_count += len(batch)
        parsed = claude_browser.extract_json(claude_browser.result_text(envelope))
        if isinstance(parsed, list):
            for entry in parsed:
                if isinstance(entry, dict):
                    findings.append({
                        "dork": str(entry.get("dork", "")),
                        "results_found": bool(entry.get("results_found", False)),
                        "top_results": entry.get("top_results", []) or [],
                        "note": str(entry.get("note", "")),
                    })
        log.info("Google dorks: batch %d/%d processed",
                 start // batch_size + 1, (len(subset) + batch_size - 1) // batch_size)

    import json as _json
    (outdir / "google_dork_findings.json").write_text(
        _json.dumps(findings, indent=2), encoding="utf-8"
    )
    hits = sum(1 for f in findings if f.get("results_found"))
    log.info("Google dorks: %d/%d queries run, %d returned results",
             run_count, len(subset), hits)
    return {"findings": findings, "count": hits, "dorks_run": run_count,
            "skipped": False, "skip_reason": ""}


async def _run_google_dorks(dorks: list[str], outdir: Path, cfg: dict) -> dict:
    log.info("Google dorks: orchestrating Claude + Chrome over %d dork(s)", len(dorks))
    return await asyncio.to_thread(_google_dorks_blocking, dorks, outdir, cfg)


# ──────────────────────────────────────────────────────────────────────────────
# Stage entry point
# ──────────────────────────────────────────────────────────────────────────────

async def enumerate_exposure(domain: str, company: str, outdir: Path, cfg: dict) -> dict:
    log.info("=== Stage 7: Exposure & Secrets Discovery ===")
    exp_cfg = cfg.get("exposure", {})

    # Always write the dork files so an operator can run them by hand.
    gm_dorks = _build_gitminer_dorks(domain)
    gd_dorks = _build_google_dorks(domain, company)

    dorks_file = outdir / "dorks.txt"
    dorks_file.write_text("\n".join(gm_dorks) + "\n", encoding="utf-8")
    google_file = outdir / "google_dorks.txt"
    google_file.write_text("\n".join(gd_dorks) + "\n", encoding="utf-8")
    log.info("Exposure: wrote %d Gitminer dorks -> dorks.txt, %d Google dorks -> google_dorks.txt",
             len(gm_dorks), len(gd_dorks))

    leakix_cfg = exp_cfg.get("leakix", {})
    gm_cfg     = exp_cfg.get("gitminer", {})
    gd_cfg     = exp_cfg.get("google_dorks", {})

    # LeakIX and Gitminer3 are independent → run concurrently.
    async def _gitminer_branch():
        if not gm_cfg.get("enabled", True):
            return {"findings": [], "count": 0, "skipped": True,
                    "skip_reason": "disabled in config", "dorks_file": str(dorks_file)}
        return await _run_gitminer(domain, outdir, gm_cfg, dorks_file)

    leakix, gitminer = await asyncio.gather(
        _run_leakix(domain, outdir, leakix_cfg),
        _gitminer_branch(),
    )

    # Google dorking (Claude+Chrome) runs after — it is browser-bound and slow.
    google = await _run_google_dorks(gd_dorks, outdir, gd_cfg)

    tool_results = [
        {"tool": "leakix", "duration": 0.0,
         "skipped": leakix.get("skipped", False), "skip_reason": leakix.get("skip_reason", "")},
        {"tool": "gitminer3", "duration": getattr(gitminer.get("tool_result"), "duration", 0.0),
         "skipped": gitminer.get("skipped", False), "skip_reason": gitminer.get("skip_reason", "")},
        {"tool": "google-dorks", "duration": 0.0,
         "skipped": google.get("skipped", False), "skip_reason": google.get("skip_reason", "")},
    ]

    # Drop the non-serializable ToolResult before returning
    gitminer.pop("tool_result", None)

    total = leakix.get("count", 0) + gitminer.get("count", 0) + google.get("count", 0)
    log.info("Exposure: leakix=%d  gitminer=%d  google_hits=%d  total=%d",
             leakix.get("count", 0), gitminer.get("count", 0),
             google.get("count", 0), total)

    return {
        "leakix": leakix,
        "gitminer": gitminer,
        "google_dorks": {**google,
                         "dorks_total": len(gd_dorks),
                         "dorks_file": str(google_file)},
        "total": total,
        "tool_results": tool_results,
    }
