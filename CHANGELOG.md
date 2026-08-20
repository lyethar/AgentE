# Changelog

All notable changes to AgentE are documented here.

## [Unreleased]

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
