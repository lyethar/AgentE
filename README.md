# AgentE

Reconnaissance workflow that orchestrates subdomain enumeration, DNS validation, screenshotting & vulnerability scanning, JavaScript crawling, asset collection, cloud infrastructure discovery, email intelligence, and external exposure/secret discovery — then consolidates everything into a set of interactive HTML reports (one per stage).

![alt text](Gemini_Generated_Image_d4iqs8d4iqs8d4iq.png)
---

## Pipeline

```
Target Domain
    │
    ├─ Stage 1 ─ Subdomain Enumeration    (subfinder · subscraper · bbot)
    │                   │ parallel
    ├─ Stage 2 ─ Validation               (dnsgen → puredns → httpx)   → live-urls.txt
    │                   │ sequential — each tool feeds the next
    ├─ Stage 3 ─ Screenshots & Vuln Scan  (gowitness screenshots + report server · nuclei) 
    │                   │ scans live URLs; never killed early
    ├─ Stage 4 ─ JS & Endpoint Crawl      (gospider · katana · waymore)
    │                   │ parallel — JS files flagged for download
    ├─ Stage 5 ─ Asset Collection         (download all JS/JSON/config incl. waymore JS, organize per asset, Prettier-format)
    │                   │ sequential — consumes Stage 5 collected JS
    ├─ Stage 6 ─ JS Analysis              (semgrep + DOM source/sink/postMessage heuristics)
    │                   │ sequential
    ├─ Stage 7 ─ Cloud Infrastructure     (cloud_enum → pycroburst)  ─┐ parallel
    ├─ Stage 8 ─ Email Intelligence        (IntelX/phonebook.cz · linkedin2username) ─┘
    │
    ├─ Stage 9 ─ Exposure & Secrets       (LeakIX · Gitminer3 · Google dorks via Tavily API)
    │
    └─ Stage 10 ─ HTML Reports (split — one file per stage under reports/)
```

---

## Quick start (Docker) — recommended

The container ships **every** external tool (Go binaries, pip/npm tools, gowitness
+ Chromium, massdns, nuclei templates, git-clone tools) so there is nothing to
install by hand. You need only Docker + Docker Compose.

```bash
git clone https://github.com/lyethar/AgentE && cd AgentE
cp .env.example .env          # fill in API keys you have (all optional)

# Prove every tool resolves inside the image:
docker compose run --rm scan --check-tools

# Run a scan against an authorized target:
docker compose run --rm scan -d example.com -c "Acme Corp"

# Reports + all stage output appear on the host under ./output/<domain>/<ts>/
# Screenshots gallery (gowitness report server):
open http://localhost:7171
```

Prefer the **published image** (no local build)? It's on GHCR:

```bash
docker pull ghcr.io/lyethar/agente:latest
docker run --rm --env-file .env -p 7171:7171 \
  -v "$PWD/output:/app/output" -v "$PWD/config.yaml:/app/config.yaml:ro" \
  ghcr.io/lyethar/agente:latest -d example.com
```

**Notes**
- **Secrets** are read from `.env` at run time and are never baked into the image.
- **`docker compose run`** (foreground, one-shot) is the right pattern — not `up`.
  Long, no-timeout tools (bbot, nuclei, waymore) can make a run lengthy.
- **Stage 8 (LinkedIn)** needs an interactive login and is **skipped automatically**
  when there is no TTY, so the default run never hangs. To run it, attach a terminal:
  `docker compose run --rm -it scan -d example.com -c "Acme Corp" --stages 8`.
- **Stop the report server** by stopping the container (`docker compose down` or
  `Ctrl-C` on the `run`) — that frees port 7171.
- **Networking:** uncomment `network_mode: host` in `docker-compose.yml` if your
  resolver/VPN setup requires it (then the `7171` port mapping is bypassed and the
  server binds the host directly).

For a fully native setup instead, see **[Native install](#native-install-fallback)** below.

---

## Native install (fallback)

Don't want containers? One command installs everything (mirrors the image):

```bash
pip install -r requirements.txt
python install_tools.py --all      # Go tools, pip tools, prettier, gowitness, git-clone tools
python orchestrator.py --check-tools
```

`--all` is idempotent and OS-aware. On Linux it also expects `massdns` (the
puredns backend) — build it from https://github.com/blechschmidt/massdns if the
pre-flight flags it missing. To install tools individually instead, use the table
below.

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
| `gowitness` | 3 | Download a release binary from https://github.com/sensepost/gowitness/releases (place it in your `PATH`) |
| `nuclei` | 3 | `sudo apt install nuclei`  *or*  `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `gospider` | 4 | `go install github.com/jaeles-project/gospider@latest` |
| `katana` | 4 | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `waymore` | 4 | `pip install waymore` — historical/archived URL discovery |
| `semgrep` | 6 | `pip install semgrep` (optional — DOM heuristics still run without it) |
| `trufflehog` | 6 | `python install_tools.py --all` ← auto-installer, OR a release binary from https://github.com/trufflesecurity/trufflehog/releases |
| `cloud_enum` | 7 | `python install_tools.py cloud_enum` ← auto-installer (the PyPI `cloud-enum` is an empty placeholder) |
| `pycroburst` | 7 | `python install_tools.py pycroburst` ← auto-installer |
| `linkedin2username` | 8 | `python install_tools.py linkedin2username` ← auto-installer |
| `gitminer3` | 9 | `python install_tools.py gitminer3` ← auto-installer (needs `GITHUB_TOKEN`) |
| `tavily-python` | 9 | `pip install tavily-python` — Google dorking via the Tavily API (needs `TAVILY_API_KEY`) |
| `prettier` | 5 | `npm install -g prettier` (optional — `npx` is used automatically if present) |

Tools that are missing are skipped gracefully at runtime — you only get output for what's installed.

> **Stage 3** (Screenshots & Vuln Scan) screenshots every live URL with `gowitness scan file -f live-urls.txt --write-db`, then launches `gowitness report server --host 0.0.0.0` as a **detached** background service (never killed — it keeps serving the screenshot gallery, default `http://0.0.0.0:7171`). In parallel it runs `nuclei -l live-urls.txt -o nuclei-results.out`; findings are parsed by host into `reports/03-nuclei.html`. Both scans run with **no timeout** so they are never killed before completing.
>
> **Stage 4** (Crawl) runs `gospider`, `katana` and `waymore` (`waymore -i <domain> -mode U -oU waymore-urs.txt`). JavaScript files — including those found only in `waymore`'s archived data — are flagged, cataloged in `reports/04-endpoints.html`, and fed to Stage 5 for download and Stage 6 for analysis.
>
> **Stage 5** (Asset Collection) needs no external binary — it uses the bundled `requests` library to download files. If `prettier` (or `npx`) is available it also pretty-prints the downloaded JavaScript for readable client-side review; if not, that step is skipped.
>
> **Stage 6** (JS Analysis) has two branches. **(i) Secrets & JS-intel:** a manual regex catalog (high-value secret patterns plus endpoints, URLs, emails and sensitive file references, with an extensive noise filter) scans the downloaded assets, and `trufflehog filesystem` adds detector-backed secret detection — results go to `reports/secrets.html`. **(ii) Static analysis:** `semgrep` (a broad set of rule packs) over the collected JavaScript plus regex-based DOM source/sink/postMessage/listener heuristics → `reports/06-js-analysis.html`. The DOM heuristics are pure Python and always run; `semgrep` and `trufflehog` degrade gracefully if absent. TruffleHog credential *verification* is off by default (it actively tests found creds against live services); enable it with `secrets.trufflehog.verify: true`.
>
> **Stage 9** (Exposure) writes its full dork lists (`dorks.txt`, `google_dorks.txt`) regardless of which tools are present. LeakIX is queried programmatically via its JSON API (key from `exposure.leakix.api_key` or the `LEAKIX_API_KEY` env var); Gitminer3 is skipped if missing; Google dorking is skipped unless `tavily-python` is installed and `TAVILY_API_KEY` is set.

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
# Export environment variables
export LEAKIX_API_KEY=".."
export GITHUB_TOKEN=".."
export INTELX_KEY=".."
export TAVILY_API_KEY=".."

# Full run — all 10 stages
python orchestrator.py -d example.com

# Include company name for LinkedIn enumeration + GitHub/Google dorks
python orchestrator.py -d example.com -c "Acme Corp"

# Resolve & validate a file of IPs/CIDRs (reverse DNS + FCrDNS), feeding FQDNs in
python orchestrator.py -d example.com --ip-list targets_ips.txt

# Scope Nuclei to just the --ip-list targets (they still get reverse-resolved,
# HTTPX-validated, and added to the full live-URL list every other tool scans;
# only Nuclei is restricted, using a separate ip-list-live-urls.txt). IPs with
# no resolvable domain name are HTTPX-probed directly and included in the Nuclei
# scope, so non-resolvable IPs are still scanned.
python orchestrator.py -d example.com --ip-list targets_ips.txt --nuclei-ip-list-only

# Run specific stages only
#   1=subs 2=validate 3=recon(gowitness+nuclei) 4=crawl 5=collect
#   6=jsanalysis 7=cloud 8=email 9=exposure 10=report
python orchestrator.py -d example.com --stages 1,2
python orchestrator.py -d example.com --stages 2,3,4,5,10   # validate, recon, crawl, collect, report
python orchestrator.py -d example.com --stages 2,3        # validate + screenshots/nuclei
python orchestrator.py -d example.com -c "Acme Corp" --stages 9,10   # exposure OSINT + report

# Run stages 3-6 stand-alone against a pre-supplied URL list (skips stages 1-2).
# Stages 3 (recon) and 4 (crawl) read these URLs directly; 5-6 chain off them.
# One URL per line; blank lines and '#' comments are ignored.
#   Required whenever --stages selects any of 3-6 without stage 2 — otherwise
#   those stages have no live URLs to run against and the tool exits with an error.
python orchestrator.py -d example.com --stages 3,4,5,6 --url-list live_urls.txt

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

# Stage 3 — screenshots (gowitness) + vulnerability scan (nuclei)
recon:
  gowitness:
    timeout: 0            # no timeout — never killed before finishing
    report_server: true   # launch `gowitness report server` (detached, never killed)
    report_host: "0.0.0.0"
  nuclei:
    timeout: 0            # no timeout
    # extra_args: ["-severity", "critical,high,medium"]

# Stage 4 — crawl; waymore pulls historical/archived URLs
js_enum:
  waymore:
    enabled: true
    mode: "U"            # -mode U = URLs only

# Stage 5 — asset download (JS/JSON/config) + Prettier formatting
collect:
  workers: 10            # concurrent download threads
  timeout: 30           # per-file HTTP timeout (seconds)
  prettier:
    enabled: true       # pretty-print downloaded JS (uses npx/global prettier)

# Stage 6 — client-side JS analysis (semgrep + DOM heuristics)
js_analysis:
  enabled: true
  timeout: 0            # per-directory semgrep timeout (0 = no limit)
  dom_scan: true        # regex DOM source/sink/postMessage/listener heuristics

# Stage 8 — IntelX phonebook search + LinkedIn username scraping
#   IntelX API key comes from the INTELX_KEY environment variable (not config)
email:
  intelx:
    maxresults: 10000
  linkedin2username:
    sleep: 30            # -s: seconds between LinkedIn page requests

# Stage 9 — exposure / secret discovery
exposure:
  leakix:
    api_key: ""              # leakix.net API key (or set LEAKIX_API_KEY env var)
  gitminer:
    github_token: ""         # GitHub PAT, or set GITHUB_TOKEN env var
  google_dorks:
    enabled: true            # via the Tavily API (TAVILY_API_KEY env var); runs ALL dorks
    search_depth: advanced   # "basic" or "advanced"
    max_results: 10          # results per dork query
    download: true           # download the discovered result files

# Optional IP -> FQDN resolution (--ip-list / -i)
ip_resolve:
  workers: 20                # concurrent reverse-DNS lookups
  timeout: 5                 # per-lookup DNS timeout (seconds)
  feed_subdomains: true      # fold validated FQDNs into the subdomain pool
  max_cidr_hosts: 4096       # cap when expanding a CIDR range
```

Full annotated config with every available option is in [`config.yaml`](config.yaml).

---

## Output

Each run writes to `output/<domain>/<timestamp>/`, with every stage in its own numbered sub-directory and all HTML reports under `reports/`:

```
output/example.com/20240501_130000/
├── reports/                    # Stage 10 — one self-contained HTML report per stage
│   ├── index.html              #   executive dashboard + links + charts (open this)
│   ├── 01-subdomains.html
│   ├── 02-live-hosts.html
│   ├── 03-nuclei.html          #   nuclei findings grouped by host
│   ├── 04-endpoints.html       #   endpoints + JS + API + waymore catalog (JS flagged)
│   ├── 05-assets.html
│   ├── 06-js-analysis.html     #   semgrep + DOM heuristics
│   ├── 07-cloud.html
│   ├── 08-email.html
│   ├── 09-exposure.html
│   ├── ip-fqdn.html
│   └── secrets.html
├── logs/
│   └── agente.log              # full debug log
├── 00-ip-resolve/              # --ip-list: PTR/FQDN/FCrDNS results
├── 01-subdomains/              # subfinder.txt, subscraper.txt, bbot_output/, subdomains_all.txt
├── 02-validation/              # dnsgen_out.txt, resolved_subdomains.txt, httpx.json, live_urls.txt
├── 03-screenshots/             # Stage 3 — gowitness
│   ├── live-urls.txt           #   input handed to gowitness + nuclei
│   ├── screenshots/            #   gowitness screenshots
│   ├── gowitness.sqlite3       #   gowitness DB (served by `report server`)
│   ├── gowitness_server.log    #   detached report-server log
│   └── nuclei-results.out      #   raw nuclei output
├── 04-crawl/                   # Stage 4 — gospider/, katana.txt, waymore-urs.txt, endpoints_all.txt
├── 05-assets/                  # Stage 5 — collected assets, organized per asset
│   └── collected/
│       ├── <asset-domain>/{js,json,config}/
│       ├── asset_manifest.json
│       └── collected_files.txt
├── 06-js-analysis/             # Stage 6 — semgrep_raw/ (raw per-directory JSON)
├── 07-cloud/                   # cloud_enum.txt, pycroburst.txt
├── 08-email/                   # emails_all.txt, usernames_all.txt, linkedin/
├── 09-exposure/                # dorks.txt, google_dork_*, leakix.json, gitminer/
├── summary.json                # machine-readable stats
└── config_snapshot.yaml        # config used for this run
```

Runs never overwrite each other — each gets its own timestamped directory. The
`gowitness report server` (Stage 3) keeps running after the scan so you can
browse the screenshot gallery at `http://0.0.0.0:7171` (see `reports/index.html`).

---

## HTML Reports

Results are **split into one self-contained HTML file per stage** under `reports/`,
so no single page is overloaded. All pages share a common dark theme and a top
navigation bar to jump between them. No server required — open `reports/index.html`
directly in a browser.

**Pages:**
- **index.html** — executive dashboard: stat cards, charts (subdomain sources, HTTP status, nuclei severity, tool times), a gowitness-server link, and quick links to every sub-report
- **01-subdomains.html** — source attribution per subdomain (includes IP-derived FQDNs, source `ptr`)
- **02-live-hosts.html** — HTTP status, page title, detected tech stack, IP
- **03-nuclei.html** — nuclei findings grouped by host, with severity, template, URL, and extracted data
- **04-endpoints.html** — all discovered URLs (JS flagged), a JS-files tab, an API-paths tab, and a **waymore** archive tab with JS-flagged historical URLs
- **05-assets.html** — per-asset download counts (JS/JSON/config) with download/skip/fail totals
- **06-js-analysis.html** — semgrep findings + DOM source/sink/postMessage heuristics per asset
- **secrets.html** — Stage 6 secret scanning: trufflehog findings (verified flagged) + regex-catalog secrets, plus endpoints/URLs/emails/file references mined from the downloaded JS
- **07-cloud.html** — S3 buckets, Azure blob storage, GCP, serverless functions
- **08-email.html** — email addresses with source, LinkedIn usernames
- **09-exposure.html** — LeakIX leaks, GitHub secret hits (Gitminer3), Google dork findings
- **ip-fqdn.html** — reverse-DNS results per supplied IP with FCrDNS validation status

All tables have live search, column sort, and pagination.

---

## Stage Reference

| # | Name | Tools | Input | Output |
|---|------|-------|-------|--------|
| 1 | Subdomain Enumeration | subfinder, subscraper, bbot | domain | `01-subdomains/subdomains_all.txt` |
| 2 | Validation | dnsgen, puredns, httpx | subdomains | `02-validation/{resolved_subdomains.txt, httpx.json, live_urls.txt}` |
| 3 | Screenshots & Vuln Scan | gowitness (+ report server), nuclei | live URLs | `03-screenshots/{screenshots/, gowitness.sqlite3, nuclei-results.out}`, `reports/03-nuclei.html` |
| 4 | JS & Endpoint Crawl | gospider, katana, waymore | live URLs + domain | `04-crawl/{endpoints_all.txt, waymore-urs.txt}` |
| 5 | Asset Collection | `requests` (built-in), Prettier (optional) | Stage 4 crawl output | `05-assets/collected/<asset>/{js,json,config}/`, `asset_manifest.json` |
| 6 | JS Analysis | semgrep + DOM heuristics; regex secret catalog + trufflehog | Stage 5 collected JS | `reports/06-js-analysis.html`, `reports/secrets.html`, `06-js-analysis/{semgrep_raw/, secrets_findings.json, trufflehog.jsonl}` |
| 7 | Cloud Infrastructure | cloud_enum, pycroburst | domain keyword | cloud asset lists |
| 8 | Email Intelligence | IntelX/phonebook.cz API, linkedin2username | domain, company | `08-email/{emails_all.txt, usernames_all.txt, linkedin/}` |
| 9 | Exposure & Secrets | LeakIX, Gitminer3, Google dorks (Tavily API) | domain, company | `09-exposure/{dorks.txt, google_dork_*, leakix.json, gitminer/}` |
| 10 | Report | — | all stage outputs | `reports/*.html` (index + per stage), `summary.json` |

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
- **Tool timeouts.** Each tool's `timeout` in `config.yaml` is in seconds; set it to `0` (or remove it) for **no timeout**, so the tool runs to completion before the next stage starts. Long-running tools (`bbot`, `gowitness`, `nuclei`, `waymore`, `cloud_enum`, `pycroburst`) ship with `timeout: 0` for this reason — they are never killed mid-scan.
- **gowitness report server.** After screenshotting (Stage 3), AgentE launches `gowitness report server --host 0.0.0.0` as a **detached** background process. It is never killed by AgentE — it keeps serving the screenshot gallery (default `http://0.0.0.0:7171`) during and after the run. Stop it yourself when you're done (e.g. by PID from the log).
- **Progress tracking.** While stages run, AgentE logs a heartbeat of which tools are still executing and for how long (e.g. `[progress] 2 tool(s) running: bbot (412s), cloud_enum (380s)`). Tune the cadence with `global.progress_interval` (seconds; `0` disables it).
- **Rate limits.** Default puredns rate is 3000 req/s. Lower it on slow networks or shared resolvers.
- **linkedin2username.** Invoked as `linkedin2username -s <sleep> -c "<company>" -n "<domain>" -o linkedin`, where `-c` is the orchestrator's `-c/--company` and `-n` is its `-d/--domain`. It authenticates through an **interactive browser login** (opens LinkedIn and waits for you to press Enter), so it runs **attached to your terminal** — its output is shown live and you can answer its prompts — and it **never times out**: the pipeline waits until it finishes on its own rather than killing it. Output lands in `<run>/linkedin/`. Tune the sleep with `email.linkedin2username.sleep`.
- **IntelX / phonebook.cz.** Email search uses the IntelX phonebook API at `https://free.intelx.io` (POST `/phonebook/search` → GET `/phonebook/search/result`). The API key is read from the **`INTELX_KEY` environment variable** — it is never stored in `config.yaml`. Without it, the phonebook search is skipped.
- **bbot presets.** The default preset runs `subdomain-enum web-basic cloud-enum email-enum`. Adjust via `subdomains.bbot.extra_args` in config.
- **Gitminer3 token.** GitHub code search needs a personal access token. Set `exposure.gitminer.github_token` or export `GITHUB_TOKEN`; without it, results will be empty.
- **Google dorking.** Stage 8 runs **all** Google dorks through the [Tavily search API](https://tavily.com) (`pip install tavily-python`; key from the `TAVILY_API_KEY` env var). For every query it catalogs the result **titles + URLs** (`google_dork_catalog.txt`, `google_dork_findings.json`) and **downloads** the discovered files into `google_dork_downloads/` with a manifest. Tune with `search_depth`, `max_results`, and `download` under `exposure.google_dorks`.
- **LeakIX.** Queried programmatically via the LeakIX JSON API, which requires authentication. Provide a key via `exposure.leakix.api_key` or the `LEAKIX_API_KEY` environment variable.
- **IP list (`--ip-list` / `-i`).** Accepts one IP or CIDR per line (inline `#` comments allowed). Each IP is reverse-resolved (PTR) and validated with forward-confirmed reverse DNS (FCrDNS) — a hostname only counts as validated if it forward-resolves back to the same IP. Validated FQDNs are merged into the subdomain pool (source `ptr`) so they flow through DNS validation and crawling. Uses the standard library resolver — no extra tools needed. CIDR expansion is capped by `ip_resolve.max_cidr_hosts`.

---

## Project Structure

```
AgentE/
├── orchestrator.py          # Entry point and async pipeline
├── install_tools.py         # Managed tool installer
├── config.yaml              # All configuration
├── requirements.txt
├── modules/
│   ├── ip_resolve.py        # Optional — IP → FQDN resolution & FCrDNS validation
│   ├── subdomains.py        # Stage 1
│   ├── validation.py        # Stage 2
│   ├── js_enum.py           # Stage 3
│   ├── collector.py         # Stage 4 — asset collection, JS download & Prettier
│   ├── js_analysis.py       # Stage 5 — semgrep + DOM heuristics on collected JS
│   ├── cloud.py             # Stage 6
│   ├── email_enum.py        # Stage 7
│   ├── exposure.py          # Stage 8 — LeakIX, Gitminer3, Google dorks
│   └── reporting.py         # Stage 9 — HTML report generator
└── utils/
    ├── runner.py            # Async subprocess runner + local tool resolution
    └── logger.py            # Colour console + file logging
```
