# Changelog

All notable changes to AgentE are documented here.

## [Unreleased]

### Added — Verbose per-command logging
- Every external command AgentE runs is now captured under `logs/`:
  - `logs/commands.log` — a chronological index (timestamp, tool, return code,
    duration, status, working dir, full command, pointer to the detail file);
    skipped/missing tools are recorded too.
  - `logs/tools/NNNN_<tool>.log` — per-invocation detail: exact command,
    start/finish timestamps, duration, return code, and full stdout/stderr.
- `agente.log` `Started` lines now echo the full command line, so the main log
  shows exactly what ran.
- New `set_tool_log_dir()` in `utils/runner.py`; the orchestrator points it at the
  run's `logs/` dir at startup. Logging never breaks a scan (failures are swallowed).

### Added — Nmap port scanning in Stage 3 (`--ip-list` scope)
- New `modules/port_scan.py`: an Nmap integration that runs **only** against the
  in-scope hosts supplied via `--ip-list`, and **before** the Nuclei scan. Two
  phases: a fast Top-N sweep (`nmap -Pn -T4 -iL … --open -v --top-ports N`), then
  a targeted service + default-script scan (`-sV -sC -p <open-ports>`) per host.
- Results feed the Stage 3 report (new Nmap section + "Open Ports" card in
  `reports/03-nuclei.html`), the console summary, `summary.json`
  (`nmap_open_ports`, `nmap_hosts_scanned`), and the Markdown report.
- Raw output written to `03-screenshots/nmap_fast.xml/.txt` and
  `nmap_service_<ip>.xml/.txt`. New `recon.nmap` config block; `nmap` added to the
  Stage 3 tool pre-flight manifest (only used with `--ip-list`).

### Added — Markdown reports + LLM analysis prompt
- New `modules/md_report.py`: Stage 10 now also writes `reports/findings.md`
  (all findings as Markdown — summary, Nmap, nuclei by severity, hosts, subdomains,
  endpoints, secrets, cloud, emails, exposures) and `reports/LLM_PROMPT.md`.
- `LLM_PROMPT.md` maps the run's folder layout, lists the tools that ran, and
  enumerates the key output files that actually exist for the run, then asks an
  LLM to propose prioritised additional manual testing grounded in the findings.

### Added — `--url-list` to run stages 3-6 without stages 1-2
- New `-u/--url-list <file>` flag: a pre-supplied list of live URLs (one per
  line; blank lines and `#` comments ignored) that seeds the downstream chain
  when stage 2 (validation) is not in `--stages`. Stage 3 (recon) and stage 4
  (crawl) read the URLs directly; stages 5-6 chain off them.
- Orchestrator now **errors out** if `--stages` selects any of stages 3-6
  without stage 2 and no `--url-list` is given — those stages otherwise have no
  live URLs to run against. If `--url-list` is passed alongside stage 2 it is
  ignored (validation generates the URLs) with a note.
- New `seed_live_urls()` in `modules/validation.py` builds the `val_data`
  structure from the URL file and writes `02-validation/live_urls.txt`, so every
  downstream stage reads it exactly as it would read stage 2's own output.

### Added — Stage 6 secrets scanning (JavaScript Analysis, branch i)
- New `modules/secrets_scan.py`: scans the downloaded assets (Stage 5) with a
  large regex catalog ported from the "JS Analyzer" Burp extension — high-value
  **secrets** plus **endpoints**, **URLs**, **emails**, and sensitive **file**
  references, behind an extensive noise-filter/validation layer. The two
  ultra-generic 32-char patterns are keyword-gated to suppress hash noise.
- Integrated **trufflehog** (`trufflehog filesystem <dir> --json`) for
  detector-backed secret detection; credential verification is off by default
  (`secrets.trufflehog.verify`). Pinned v3.97.0 in the image and installer.
- Owns `reports/secrets.html` (trufflehog + regex secrets + JS-mined intel),
  writes `secrets_findings.json` and `trufflehog.jsonl`. Runs in parallel with
  the existing semgrep + DOM analysis (branch ii, unchanged).
- `trufflehog` added to the pre-flight manifest, `install_tools.py --all`, the
  Dockerfile, and `config.yaml` (`secrets:` section).

### Added — Packaging & Containerization
- **Docker**: multi-stage `Dockerfile` (Go builder + `python:3.10-slim` runtime)
  that bundles every external tool — Go binaries, pip/npm tools, gowitness +
  Chromium, massdns (puredns backend), nuclei templates, and the git-clone tools —
  so AgentE is clone-and-run with no manual install.
- `docker-compose.yml` `scan` service wiring `.env` secrets, the `7171` gowitness
  report-server port, and host volumes for `output/`, `config.yaml`, `wordlists/`.
- `entrypoint.sh`, `.env.example`, `.dockerignore`.
- `install_tools.py --all`: native full-install fallback (Go tools, pip tools,
  prettier, gowitness, git-clone tools) mirroring the image; idempotent + OS-aware.
- `.github/workflows/docker.yml`: build image on PRs, publish to
  `ghcr.io/lyethar/agente` on version tags, `--check-tools` smoke test, and a
  native-parity job.
- `wordlists/resolvers.txt` default resolver list for puredns.
- `docs/packaging-plan.md`.

### Added — Recon pipeline (prerequisite work on this branch)
- **Stage 3 — Screenshots & Vuln Scan**: gowitness screenshots + detached report
  server, nuclei scan grouped by host (`reports/03-nuclei.html`). All later stages
  renumbered (pipeline is now 10 stages).
- **Stage 4 — waymore** archived-URL discovery, with JS files flagged, downloaded,
  and analysed downstream.
- Output restructured into per-stage numbered directories; HTML report **split**
  into one self-contained file per stage under `reports/`.

### Changed
- `orchestrator.py`: `-d/--domain` is now optional for `--check-tools` /
  `--install-tools` (so `docker run agente --check-tools` works).
- Stage 8 `linkedin2username` is **auto-skipped when no interactive TTY** is
  available, so the default (containerized/CI) run never hangs on its login prompt.
  Override with `email.linkedin2username.force: true`.

### Fixed
- `validation.py` no longer hard-codes `/usr/bin/httpx`; httpx resolves via PATH /
  `tools/bin` so it works both natively and in the image.
