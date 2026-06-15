"""
Stage 5 — Email & Username Enumeration
Tools: phonebooks.cz (API), linkedin2username (CLI)
"""
import asyncio
import json
import logging
import re
import urllib.parse
import urllib.request
from pathlib import Path

from utils.runner import ToolResult, run_tool

log = logging.getLogger("agente.email")

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


# ──────────────────────────────────────────────────────────────────────────────
# phonebooks.cz — public OSINT email search API
# ──────────────────────────────────────────────────────────────────────────────

def _query_phonebooks(domain: str, cfg: dict) -> list[str]:
    """
    Queries phonebooks.cz for email addresses tied to a domain.
    Returns a deduplicated list of discovered email addresses.
    """
    base_url = "https://phonebook.cz/api/v1/intelligence/search"
    params = urllib.parse.urlencode({
        "term": domain,
        "type": "email",
        "page": 1,
    })
    api_key = cfg.get("api_key", "")
    headers = {
        "User-Agent": "AgentE-Recon/1.0",
        **({"X-Api-Key": api_key} if api_key else {}),
    }

    emails: set[str] = set()
    max_pages = cfg.get("max_pages", 5)

    for page in range(1, max_pages + 1):
        paged_params = urllib.parse.urlencode({"term": domain, "type": "email", "page": page})
        url = f"{base_url}?{paged_params}"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())

            # Response shape: {"results": [...], "total": N, "page": P}
            items = data.get("results", data.get("data", []))
            if not items:
                break
            for item in items:
                # item may be a string or {"email": "...", ...}
                if isinstance(item, str):
                    if _EMAIL_RE.match(item):
                        emails.add(item.lower())
                elif isinstance(item, dict):
                    for field in ("email", "value", "address"):
                        val = item.get(field, "")
                        if val and _EMAIL_RE.match(val):
                            emails.add(val.lower())
        except Exception as exc:
            log.warning("phonebooks.cz request failed (page %d): %s", page, exc)
            break

    return sorted(emails)


# ──────────────────────────────────────────────────────────────────────────────
# linkedin2username
# ──────────────────────────────────────────────────────────────────────────────

async def run_linkedin2username(company: str, domain: str, outdir: Path, cfg: dict) -> ToolResult:
    """
    linkedin2username: generates username permutations from LinkedIn employee data.
    Requires a LinkedIn session cookie or credentials in config.
    """
    out_file = outdir / "linkedin_usernames.txt"
    cmd = [
        "linkedin2username",
        "-c", company,
        "-d", domain,
        "-o", str(out_file),
        *cfg.get("extra_args", []),
    ]
    if cfg.get("cookie"):
        cmd += ["-s", cfg["cookie"]]
    return await run_tool(cmd, "linkedin2username", timeout=cfg.get("timeout"))


def _parse_usernames(outdir: Path) -> list[str]:
    ul_file = outdir / "linkedin_usernames.txt"
    if not ul_file.exists():
        return []
    return [line.strip() for line in ul_file.read_text(errors="replace").splitlines() if line.strip()]


def _derive_emails(usernames: list[str], domain: str) -> list[str]:
    """Build email candidates from username list + domain."""
    return [f"{u}@{domain}" for u in usernames if u]


async def enumerate_emails(domain: str, company: str, outdir: Path, cfg: dict) -> dict:
    log.info("=== Stage 5: Email & Username Enumeration ===")
    email_cfg = cfg.get("email", {})

    # Run phonebooks.cz synchronously (urllib) + linkedin2username async
    loop = asyncio.get_event_loop()

    pb_emails_fut = loop.run_in_executor(
        None, _query_phonebooks, domain, email_cfg.get("phonebooks", {})
    )
    li_result_fut = run_linkedin2username(
        company, domain, outdir, email_cfg.get("linkedin2username", {})
    )

    pb_emails, li_result = await asyncio.gather(pb_emails_fut, li_result_fut)

    usernames    = _parse_usernames(outdir)
    li_emails    = _derive_emails(usernames, domain)
    all_emails   = sorted(set(pb_emails) | set(li_emails))

    # Persist results
    email_file = outdir / "emails_all.txt"
    email_file.write_text("\n".join(all_emails), encoding="utf-8")

    user_file = outdir / "usernames_all.txt"
    user_file.write_text("\n".join(usernames), encoding="utf-8")

    log.info(
        "Emails: phonebooks=%d  linkedin_derived=%d  total=%d  usernames=%d",
        len(pb_emails), len(li_emails), len(all_emails), len(usernames),
    )

    return {
        "emails":           all_emails,
        "usernames":        usernames,
        "phonebooks_count": len(pb_emails),
        "linkedin_count":   len(li_emails),
        "emails_file":      str(email_file),
        "tool_results": [
            {"tool": "phonebooks.cz", "duration": 0.0, "skipped": False, "skip_reason": ""},
            {"tool": li_result.tool,  "duration": li_result.duration,
             "skipped": li_result.skipped, "skip_reason": li_result.skip_reason},
        ],
    }
