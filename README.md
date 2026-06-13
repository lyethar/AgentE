# AgentE

Agentic reconnaissance workflow that orchestrates subdomain enumeration, DNS validation, JavaScript crawling, asset collection, cloud infrastructure discovery, email intelligence, and external exposure/secret discovery — then consolidates everything into an interactive HTML report.

---

## Pipeline

```
Target Domain
    │
    ├─ Stage 1 ─ Subdomain Enumeration    (subfinder · subscraper · bbot)
    │                   │ parallel
    ├─ Stage 2 ─ Validation               (dnsgen → puredns → httpx)
    │                   │ sequential — each tool feeds the next
    ├─ Stage 3 ─ JS & Endpoint Crawl      (gospider · katana)
    │                   │ parallel
    ├─ Stage 4 ─ Asset Collection         (download all JS/JSON/config, organize per asset, Prettier-format JS)
    │                   │ sequential — consumes Stage 3 crawl output
    ├─ Stage 5 ─ Cloud Infrastructure     (cloud_enum → pycroburst)  ─┐ parallel
    ├─ Stage 6 ─ Email Intelligence        (phonebooks.cz · linkedin2username) ─┘
    │
    ├─ Stage 7 ─ Exposure & Secrets       (LeakIX · Gitminer3 · Google dorks via Claude + Chrome)
    │
    └─ Stage 8 ─ HTML Report
```

---

## Requirements

**Python 3.10+**

```
pip install -r requirements.txt
```

**External tools** — install each based on your OS:

| Tool | Stage | Install |
|------|-------|---------|
| `subfinder` | 1 | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `subscraper` | 1 | `pip install subscraper` |
| `bbot` | 1 | `pip install bbot` |
| `dnsgen` | 2 | `pip install dnsgen` |
| `puredns` | 2 | `go install github.com/d3mondev/puredns/v2@latest` |
| `httpx` | 2 | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `gospider` | 3 | `go install github.com/jaeles-project/gospider@latest` |
| `katana` | 3 | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `cloud_enum` | 5 | `pip install cloud-enum` |
| `pycroburst` | 5 | `python install_tools.py pycroburst` ← auto-installer |
| `linkedin2username` | 6 | `python install_tools.py linkedin2username` ← auto-installer |
| `gitminer3` | 7 | `python install_tools.py gitminer3` ← auto-installer (needs `GITHUB_TOKEN`) |
| `claude` | 7 | [Claude Code CLI](https://claude.com/claude-code) with `--chrome` — drives Google dork lookups |
| `prettier` | 4 | `npm install -g prettier` (optional — `npx` is used automatically if present) |

Tools that are missing are skipped gracefully at runtime — you only get output for what's installed.

> **Stage 4** (Asset Collection) needs no external binary — it uses the bundled `requests` library to download files. If `prettier` (or `npx`) is available it also pretty-prints the downloaded JavaScript for readable client-side review; if not, that step is skipped.
>
> **Stage 7** (Exposure) writes its full dork lists (`dorks.txt`, `google_dorks.txt`) regardless of which tools are present. LeakIX is queried programmatically via its JSON API (key from `exposure.leakix.api_key` or the `LEAKIX_API_KEY` env var); Gitminer3 and Google dorking are skipped if their tools are missing.

---

## Installation

```bash
git clone https://github.com/lyethar/AgentE
cd AgentE
pip install -r requirements.txt

# Install git-cloned tools
python install_tools.py
```

### Managed tool installer

`pycroburst` and `linkedin2username` require git cloning. The installer handles cloning, pip install, and writing runnable wrappers automatically:

```bash
# Install both
python install_tools.py

# Install individually (accepts aliases)
python install_tools.py pycroburst
python install_tools.py l2u

# Check what's installed
python install_tools.py --list

# Force re-clone
python install_tools.py --reinstall
```

Wrappers are written to `tools/bin/` and resolved automatically at runtime — no PATH changes needed.

---

## Usage

```bash
# Full run — all 8 stages
python orchestrator.py -d example.com

# Include company name for LinkedIn enumeration + GitHub/Google dorks
python orchestrator.py -d example.com -c "Acme Corp"

# Run specific stages only
#   1=subs 2=validate 3=js 4=collect 5=cloud 6=email 7=exposure 8=report
python orchestrator.py -d example.com --stages 1,2
python orchestrator.py -d example.com --stages 3,4,8      # crawl, download JS, report
python orchestrator.py -d example.com -c "Acme Corp" --stages 7,8   # exposure OSINT + report

# Check which tools are installed before running
python orchestrator.py -d example.com --check-tools

# Install managed tools from within the orchestrator
python orchestrator.py -d example.com --install-tools

# Skip missing tools without prompting (useful in CI)
python orchestrator.py -d example.com --skip-missing

# Verbose logging + custom config + custom output dir
python orchestrator.py -d example.com -v --config my.yaml -o /tmp/recon
```

---

## Configuration

All tool flags, timeouts, wordlists, and credentials live in [`config.yaml`](config.yaml). Nothing is hardcoded.

```yaml
# Stage 2 — tune DNS resolution rate and resolver list
validation:
  puredns:
    rate_limit: 3000
    resolvers: "/opt/wordlists/resolvers.txt"

# Stage 2 — extra httpx flags (e.g. screenshots)
  httpx:
    threads: 50
    extra_args: ["-screenshot", "-screenshot-timeout", "10"]

# Stage 4 — asset download (JS/JSON/config) + Prettier formatting
collect:
  workers: 10            # concurrent download threads
  timeout: 30           # per-file HTTP timeout (seconds)
  prettier:
    enabled: true       # pretty-print downloaded JS (uses npx/global prettier)

# Stage 6 — LinkedIn session cookie + phonebooks.cz API key
email:
  phonebooks:
    api_key: "YOUR_KEY_HERE"
  linkedin2username:
    cookie: "YOUR_LI_AT_COOKIE"

# Stage 7 — exposure / secret discovery
exposure:
  leakix:
    api_key: ""              # leakix.net API key (or set LEAKIX_API_KEY env var)
  gitminer:
    github_token: ""         # GitHub PAT, or set GITHUB_TOKEN env var
  google_dorks:
    enabled: true            # needs the `claude` CLI with --chrome
    max_dorks: 20            # Google rate-limits aggressive automated dorking
    max_budget_usd: 2.0      # spend cap per Claude browser batch
```

Full annotated config with every available option is in [`config.yaml`](config.yaml).

---

## Output

Each run writes to `output/<domain>/<timestamp>/`:

```
output/example.com/20240501_130000/
├── subdomains_all.txt        # merged deduplicated subdomains
├── subfinder.txt             # per-tool raw output
├── subscraper.txt
├── bbot_output/
├── dnsgen_out.txt            # permutation candidates
├── resolved_subdomains.txt   # DNS-verified live subdomains
├── httpx.json                # HTTP probe results (JSON lines)
├── live_urls.txt             # input for crawlers
├── gospider/                 # crawler output
├── katana.txt
├── endpoints_all.txt         # merged crawled URLs
├── collected/                # Stage 4 — downloaded assets, organized per asset
│   ├── <asset-domain>/
│   │   ├── js/               # downloaded JavaScript (Prettier-formatted)
│   │   ├── json/             # downloaded JSON
│   │   └── config/           # downloaded config-like files
│   ├── asset_manifest.json   # every download: url, asset, kind, path, status
│   └── collected_files.txt   # human-readable directory listing
├── cloud_enum.txt
├── pycroburst.txt
├── emails_all.txt
├── usernames_all.txt
├── dorks.txt                 # Stage 7 — Gitminer3 dorks (domain-scoped)
├── google_dorks.txt          # Stage 7 — Google dork list (domain/company-scoped)
├── leakix.json               # Stage 7 — raw LeakIX results
├── google_dork_findings.json # Stage 7 — Google dork findings (Claude + Chrome)
├── gitminer/                 # Stage 7 — Gitminer3 downloads, CSV + markdown report
├── report_example.com.html   # interactive HTML report
├── summary.json              # machine-readable stats
├── config_snapshot.yaml      # config used for this run
└── agente.log                # full debug log
```

Runs never overwrite each other — each gets its own timestamped directory.

---

## HTML Report

The report is a self-contained single HTML file. No server required — open it directly in a browser.

**Sections:**
- **Dashboard** — stat cards for subdomains, live hosts, endpoints, JS collected, cloud assets, emails, exposures, secrets
- **Charts** — subdomain source breakdown, HTTP status distribution, tool execution times
- **Subdomains** — filterable table with source attribution per subdomain
- **Live Hosts** — HTTP status, page title, detected tech stack, IP
- **Endpoints** — all discovered URLs, JS files tab, API paths tab
- **Collected Assets** — per-asset download counts (JS/JSON/config) with download/skip/fail totals
- **Cloud** — S3 buckets, Azure blob storage, GCP, serverless functions
- **Email Intel** — email addresses with source, LinkedIn usernames
- **Exposure OSINT** — LeakIX leaks, GitHub secret hits (Gitminer3), and Google dork findings
- **Secrets** — regex-matched patterns from crawled JS (verify manually)

All tables have live search, column sort, and pagination.

---

## Stage Reference

| # | Name | Tools | Input | Output |
|---|------|-------|-------|--------|
| 1 | Subdomain Enumeration | subfinder, subscraper, bbot | domain | `subdomains_all.txt` |
| 2 | Validation | dnsgen, puredns, httpx | subdomains | `resolved_subdomains.txt`, `httpx.json`, `live_urls.txt` |
| 3 | JS & Endpoint Crawl | gospider, katana | live URLs | `endpoints_all.txt` |
| 4 | Asset Collection | `requests` (built-in), Prettier (optional) | Stage 3 crawl output | `collected/<asset>/{js,json,config}/`, `asset_manifest.json` |
| 5 | Cloud Infrastructure | cloud_enum, pycroburst | domain keyword | cloud asset lists |
| 6 | Email Intelligence | phonebooks.cz API, linkedin2username | domain, company | `emails_all.txt`, `usernames_all.txt` |
| 7 | Exposure & Secrets | LeakIX, Gitminer3, Google dorks (Claude + Chrome) | domain, company | `dorks.txt`, `google_dorks.txt`, `leakix.json`, `gitminer/` |
| 8 | Report | — | all stage outputs | `report_<domain>.html`, `summary.json` |

---

## Pre-flight Check

Before any scan, AgentE checks which tools are installed and tells you exactly how to get the missing ones:

```
  Tool Pre-flight Check
  -----------------------------------------
  [+]  subfinder           stage 1
  [-]  subscraper          stage 1
  [+]  bbot                stage 1
  ...
  Found: 9/13  |  Missing: 4

  Auto-installable (git clone + pip):
    pycroburst          python install_tools.py pycroburst
    linkedin2username   python install_tools.py linkedin2username
    gitminer3           python install_tools.py gitminer3

  Install manually:
    subscraper          pip install subscraper

  Continue anyway? [y/N]
```

Pass `--skip-missing` to suppress the prompt and proceed automatically.

---

## Notes

- **Authorized use only.** Run AgentE only against targets you have explicit permission to test.
- **Rate limits.** Default puredns rate is 3000 req/s. Lower it on slow networks or shared resolvers.
- **LinkedIn cookie.** `linkedin2username` requires a valid `li_at` session cookie. Set it in `config.yaml` under `email.linkedin2username.cookie`.
- **phonebooks.cz.** Works unauthenticated but an API key raises the page limit. Set it under `email.phonebooks.api_key`.
- **bbot presets.** The default preset runs `subdomain-enum web-basic cloud-enum email-enum`. Adjust via `subdomains.bbot.extra_args` in config.
- **Gitminer3 token.** GitHub code search needs a personal access token. Set `exposure.gitminer.github_token` or export `GITHUB_TOKEN`; without it, results will be empty.
- **Google dorking.** Stage 7 drives the `claude` CLI with `--chrome` to run Google dorks. Google rate-limits automated searches, so `max_dorks` is capped by default and CAPTCHA'd queries are flagged for manual follow-up. Spend/iterations are bounded via `max_budget_usd` / `max_turns`.
- **LeakIX.** Queried programmatically via the LeakIX JSON API, which requires authentication. Provide a key via `exposure.leakix.api_key` or the `LEAKIX_API_KEY` environment variable.

---

## Project Structure

```
AgentE/
├── orchestrator.py          # Entry point and async pipeline
├── install_tools.py         # Managed tool installer
├── config.yaml              # All configuration
├── requirements.txt
├── modules/
│   ├── subdomains.py        # Stage 1
│   ├── validation.py        # Stage 2
│   ├── js_enum.py           # Stage 3
│   ├── collector.py         # Stage 4 — asset collection, JS download & Prettier
│   ├── cloud.py             # Stage 5
│   ├── email_enum.py        # Stage 6
│   ├── exposure.py          # Stage 7 — LeakIX, Gitminer3, Google dorks
│   └── reporting.py         # Stage 8 — HTML report generator
└── utils/
    ├── runner.py            # Async subprocess runner + local tool resolution
    ├── claude_browser.py    # Claude Code + Chrome bridge (Google dorks)
    └── logger.py            # Colour console + file logging
```
