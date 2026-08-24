# Changelog

All notable changes to AgentE are documented here.

## [Unreleased]

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
