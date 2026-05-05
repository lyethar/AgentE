# AgentE

Agentic reconnaissance workflow that orchestrates subdomain enumeration, DNS validation, JavaScript crawling, cloud infrastructure discovery, and email intelligence — then consolidates everything into an interactive HTML report.

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
    ├─ Stage 4 ─ Cloud Infrastructure     (cloud_enum → pycroburst)  ─┐ parallel
    ├─ Stage 5 ─ Email Intelligence        (phonebooks.cz · linkedin2username) ─┘
    │
    └─ Stage 6 ─ HTML Report
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
| `cloud_enum` | 4 | `pip install cloud-enum` |
| `pycroburst` | 4 | `python install_tools.py pycroburst` ← auto-installer |
| `linkedin2username` | 5 | `python install_tools.py linkedin2username` ← auto-installer |

Tools that are missing are skipped gracefully at runtime — you only get output for what's installed.

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
# Full run — all 6 stages
python orchestrator.py -d example.com

# Include company name for LinkedIn enumeration
python orchestrator.py -d example.com -c "Acme Corp"

# Run specific stages only
python orchestrator.py -d example.com --stages 1,2
python orchestrator.py -d example.com --stages 3,4,5,6

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

# Stage 5 — LinkedIn session cookie + phonebooks.cz API key
email:
  phonebooks:
    api_key: "YOUR_KEY_HERE"
  linkedin2username:
    cookie: "YOUR_LI_AT_COOKIE"
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
├── cloud_enum.txt
├── pycroburst.txt
├── emails_all.txt
├── usernames_all.txt
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
- **Dashboard** — stat cards for subdomains, live hosts, endpoints, cloud assets, emails, secrets
- **Charts** — subdomain source breakdown, HTTP status distribution, tool execution times
- **Subdomains** — filterable table with source attribution per subdomain
- **Live Hosts** — HTTP status, page title, detected tech stack, IP
- **Endpoints** — all discovered URLs, JS files tab, API paths tab
- **Cloud** — S3 buckets, Azure blob storage, GCP, serverless functions
- **Email Intel** — email addresses with source, LinkedIn usernames
- **Secrets** — regex-matched patterns from crawled JS (verify manually)

All tables have live search, column sort, and pagination.

---

## Stage Reference

| # | Name | Tools | Input | Output |
|---|------|-------|-------|--------|
| 1 | Subdomain Enumeration | subfinder, subscraper, bbot | domain | `subdomains_all.txt` |
| 2 | Validation | dnsgen, puredns, httpx | subdomains | `resolved_subdomains.txt`, `httpx.json`, `live_urls.txt` |
| 3 | JS & Endpoint Crawl | gospider, katana | live URLs | `endpoints_all.txt` |
| 4 | Cloud Infrastructure | cloud_enum, pycroburst | domain keyword | cloud asset lists |
| 5 | Email Intelligence | phonebooks.cz API, linkedin2username | domain, company | `emails_all.txt`, `usernames_all.txt` |
| 6 | Report | — | all stage outputs | `report_<domain>.html`, `summary.json` |

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
  Found: 8/11  |  Missing: 3

  Auto-installable (git clone + pip):
    pycroburst          python install_tools.py pycroburst
    linkedin2username   python install_tools.py linkedin2username

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
│   ├── cloud.py             # Stage 4
│   ├── email_enum.py        # Stage 5
│   └── reporting.py         # Stage 6 — HTML report generator
└── utils/
    ├── runner.py            # Async subprocess runner + local tool resolution
    └── logger.py            # Colour console + file logging
```
