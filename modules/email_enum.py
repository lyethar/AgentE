"""
Stage 7 — Email & Username Enumeration
Tools: IntelX / phonebook.cz phonebook API, linkedin2username (CLI)
"""
import asyncio
import json
import logging
import os
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path

from utils.runner import ToolResult, run_tool

log = logging.getLogger("agente.email")

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# ──────────────────────────────────────────────────────────────────────────────
# IntelX / phonebook.cz — phonebook search API (https://free.intelx.io)
#
# The API key is read from the INTELX_KEY environment variable — it is never
# stored in config.yaml. Flow (mirrors phonebook.cz):
#   1. POST /phonebook/search?k=<KEY>  with a JSON body → returns a search id.
#   2. GET  /phonebook/search/result?k=<KEY>&id=<id>&limit=N → JSON of results.
# ──────────────────────────────────────────────────────────────────────────────

_INTELX_BASE = "https://free.intelx.io"

# Browser-like headers matching a phonebook.cz result fetch.
_INTELX_HEADERS = {
    "accept": "*/*",
    "accept-language": "en-US,en;q=0.9",
    "origin": "https://phonebook.cz",
    "referer": "https://phonebook.cz/",
    "user-agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"),
}


def _extract_intelx_emails(data) -> set[str]:
    """Pull every email address out of an IntelX phonebook result payload."""
    emails: set[str] = set()

    def _add(value):
        if isinstance(value, str):
            for match in _EMAIL_RE.findall(value):
                emails.add(match.lower())

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = (data.get("selectors") or data.get("results")
                 or data.get("data") or [])
    else:
        items = []

    for item in items:
        if isinstance(item, str):
            _add(item)
        elif isinstance(item, dict):
            for key in ("selectorvalue", "selector", "value", "email", "address"):
                _add(item.get(key, ""))
    return emails


def _query_intelx(domain: str, cfg: dict) -> list[str]:
    """
    Query the IntelX phonebook API for email addresses tied to *domain*.

    Returns a deduplicated, sorted list of discovered email addresses. The API
    key comes from the INTELX_KEY environment variable; if it is unset the query
    is skipped (with a warning) rather than sent unauthenticated.
    """
    api_key = os.environ.get("INTELX_KEY", "")
    if not api_key:
        log.warning("IntelX: no API key — set the INTELX_KEY environment variable "
                    "to enable phonebook email search")
        return []

    maxresults = int(cfg.get("maxresults", 10000))
    search_timeout = int(cfg.get("timeout", 20))
    key_q = urllib.parse.quote(api_key, safe="")

    # ── 1. POST: start a phonebook search, get an id ──
    search_url = f"{_INTELX_BASE}/phonebook/search?k={key_q}"
    payload = json.dumps({
        "term": domain,
        "maxresults": maxresults,
        "media": 0,
        "target": 2,             # 2 = return email selectors
        "terminate": [None],
        "timeout": search_timeout,
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            search_url, data=payload, method="POST",
            headers={"Content-Type": "application/json", **_INTELX_HEADERS},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            start = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        log.warning("IntelX search POST failed: %s", exc)
        return []

    search_id = start.get("id") if isinstance(start, dict) else None
    if not search_id:
        log.warning("IntelX: no search id returned (status=%s)",
                    start.get("status") if isinstance(start, dict) else "?")
        return []
    log.info("IntelX: search id %s for term '%s'", search_id, domain)

    # ── 2. GET: pull results, polling until the search reports it is finished ──
    id_q = urllib.parse.quote(str(search_id), safe="")
    limit = int(cfg.get("limit", maxresults))
    max_polls = int(cfg.get("max_polls", 20))
    result_url = (f"{_INTELX_BASE}/phonebook/search/result?"
                  f"k={key_q}&id={id_q}&limit={limit}")

    emails: set[str] = set()
    prev_count, stable = -1, 0
    for _ in range(max_polls):
        try:
            req = urllib.request.Request(result_url, headers=_INTELX_HEADERS)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            log.warning("IntelX result GET failed: %s", exc)
            break

        emails |= _extract_intelx_emails(data)
        status = data.get("status") if isinstance(data, dict) else None

        if status == 2:                       # search id not found
            break
        if status == 1:                       # no more results — finished
            break
        # status 0 (success) / 3 (still running): keep polling until stable
        if len(emails) == prev_count:
            stable += 1
            if stable >= 2:
                break
        else:
            stable = 0
        prev_count = len(emails)
        time.sleep(1)

    return sorted(emails)


# ──────────────────────────────────────────────────────────────────────────────
# linkedin2username
# ──────────────────────────────────────────────────────────────────────────────

async def run_linkedin2username(company: str, domain: str, outdir: Path, cfg: dict) -> ToolResult:
    """
    linkedin2username: scrapes LinkedIn employees for a company and writes
    username-format files. Invocation mirrors:

        python3 linkedin2username.py -s 30 -c "<company>" -o linkedin

      -c  company slug (matches the orchestrator's -c/--company)
      -s  seconds to sleep between page requests
      -o  output directory (created under the run directory)

    Output files land in ``<run>/linkedin/<company>-<format>.txt``.
    """
    cmd = [
        "linkedin2username",
        "-s", str(cfg.get("sleep", 30)),
        "-c", company,
        "-o", "linkedin",
        *cfg.get("extra_args", []),
    ]
    # Run inside the run directory so `-o linkedin` writes to <run>/linkedin/.
    return await run_tool(cmd, "linkedin2username", cwd=outdir, timeout=cfg.get("timeout"))


def _parse_linkedin_output(outdir: Path) -> list[str]:
    """
    Collect username candidates from the linkedin2username output directory.

    linkedin2username writes one file per username format
    (``<company>-flast.txt``, ``<company>-first.last.txt``, …) plus
    ``-rawnames.txt`` (full names) and ``-metadata.txt`` (CSV) which are skipped.
    """
    li_dir = outdir / "linkedin"
    usernames: set[str] = set()

    if li_dir.is_dir():
        for f in sorted(li_dir.glob("*.txt")):
            if f.name.endswith("-rawnames.txt") or f.name.endswith("-metadata.txt"):
                continue
            for line in f.read_text(errors="replace").splitlines():
                line = line.strip()
                if line and "," not in line:
                    usernames.add(line)

    return sorted(usernames)


def _derive_emails(usernames: list[str], domain: str) -> list[str]:
    """Build email candidates from the username list + domain."""
    out = []
    for u in usernames:
        if not u:
            continue
        out.append(u if "@" in u else f"{u}@{domain}")
    return out


async def enumerate_emails(domain: str, company: str, outdir: Path, cfg: dict) -> dict:
    log.info("=== Stage 7: Email & Username Enumeration ===")
    email_cfg = cfg.get("email", {})
    intelx_cfg = email_cfg.get("intelx", email_cfg.get("phonebooks", {}))

    # Run IntelX synchronously (urllib) + linkedin2username async
    loop = asyncio.get_event_loop()

    ix_emails_fut = loop.run_in_executor(None, _query_intelx, domain, intelx_cfg)
    li_result_fut = run_linkedin2username(
        company, domain, outdir, email_cfg.get("linkedin2username", {})
    )

    ix_emails, li_result = await asyncio.gather(ix_emails_fut, li_result_fut)

    usernames    = _parse_linkedin_output(outdir)
    li_emails    = _derive_emails(usernames, domain)
    all_emails   = sorted(set(ix_emails) | set(li_emails))

    # Persist results
    email_file = outdir / "emails_all.txt"
    email_file.write_text("\n".join(all_emails), encoding="utf-8")

    user_file = outdir / "usernames_all.txt"
    user_file.write_text("\n".join(usernames), encoding="utf-8")

    log.info(
        "Emails: intelx=%d  linkedin_derived=%d  total=%d  usernames=%d",
        len(ix_emails), len(li_emails), len(all_emails), len(usernames),
    )

    return {
        "emails":           all_emails,
        "usernames":        usernames,
        "phonebooks_count": len(ix_emails),
        "linkedin_count":   len(li_emails),
        "emails_file":      str(email_file),
        "tool_results": [
            {"tool": "intelx", "duration": 0.0, "skipped": not ix_emails,
             "skip_reason": "" if ix_emails else "no results / INTELX_KEY unset"},
            {"tool": li_result.tool,  "duration": li_result.duration,
             "skipped": li_result.skipped, "skip_reason": li_result.skip_reason},
        ],
    }
