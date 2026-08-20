# AgentE — Packaging & Containerization

Reference for how AgentE is packaged so it is **clone-and-run** with no manual,
multi-ecosystem tool install. Primary mechanism: Docker (multi-stage image +
Compose + a published GHCR image). Secondary: a native `install_tools.py --all`
bootstrap.

> Authorized-use tool. Packaging changes only *how* the framework and its
> dependencies are installed and run — never its scope.

## Objective & success criteria

1. One command runs the full pipeline: `docker compose run --rm scan -d example.com`.
2. HTML reports + all stage output land on the host and survive container exit.
3. The gowitness report server is reachable from the host browser (`:7171`).
4. API keys are configured once via `.env`; no secrets baked into the image.
5. A prebuilt image is published to `ghcr.io/lyethar/agente` on each tagged release.
6. Non-containerizable components (interactive LinkedIn login) are documented with
   a supported workaround, and the default run never hangs on them.
7. A native `install_tools.py --all` fallback exists and is exercised in CI.

## Architecture

```
docker compose ─► go-builder (golang:1.22-bookworm)
                    go install all Go tools → /go/bin
                    build massdns (puredns backend)
                         │  COPY --from=builder
                    final (python:3.10-slim-bookworm)
                    + chromium, node/npm, git
                    + pip -r requirements.txt + pip recon tools
                    + npm i -g prettier
                    + install_tools.py (git-clone tools)
                    + gowitness release binary (pinned)
                    + nuclei -update-templates
                    ENTRYPOINT → entrypoint.sh → orchestrator.py

host ./output      ─► /app/output
host ./config.yaml ─► /app/config.yaml (ro)
host ./wordlists   ─► /opt/wordlists (ro)
.env (API keys)    ─► environment
localhost:7171     ◄─ gowitness report server
```

## Delivered artifacts

| Artifact | Purpose |
|---|---|
| `Dockerfile` | Multi-stage build; pinned Go versions (build-arg overridable); massdns from source; gowitness pinned (optional `GOWITNESS_SHA256` checksum); `nuclei -update-templates` |
| `entrypoint.sh` | `exec python orchestrator.py "$@"` |
| `docker-compose.yml` | `scan` service: `.env`, port `7171`, `output`/`config.yaml`/`wordlists` volumes |
| `.env.example` | The four API-key env vars |
| `.dockerignore` | Excludes `output/`, `.git`, venvs, `tools/`, secrets |
| `install_tools.py --all` | Native full install: Go tools, pip tools, prettier, gowitness, git-clone tools |
| `.github/workflows/docker.yml` | Build on PR; push to GHCR on tags; `--check-tools` smoke test; native-parity job |
| `wordlists/resolvers.txt` | Default puredns resolver list mounted at `/opt/wordlists` |

## Dependency contract

The image must satisfy every tool the orchestrator's pre-flight expects. Source
of truth: `orchestrator.py` `TOOL_MANIFEST` + `config.yaml`. Version pins live in
the `Dockerfile` (Go tools, gowitness) and `install_tools.py` (`GO_TOOLS`,
`PIP_TOOLS`, `GOWITNESS_VERSION`) — keep the two in sync.

System-level requirements: Chromium (gowitness), Node/npm (prettier), git
(git-clone installer), massdns (puredns backend), nuclei templates, a resolver
wordlist. Runtime secrets: `LEAKIX_API_KEY`, `GITHUB_TOKEN`, `INTELX_KEY`,
`TAVILY_API_KEY`.

## Handling the awkward components

- **gowitness + Chromium** — image installs `chromium`; `CHROME_PATH` /
  `GOWITNESS_CHROME_PATH` point gowitness at it. Validate a screenshot is actually
  produced (most common silent failure).
- **puredns + massdns** — puredns shells out to massdns; it is built in the
  builder stage and copied to `/usr/local/bin`. Mount a real `resolvers.txt` via
  the `wordlists` volume and point `config.yaml` at `/opt/wordlists/resolvers.txt`.
- **linkedin2username (Stage 8)** — interactive browser login; cannot run in a
  headless one-shot container. Handling: the orchestrator **auto-skips it when
  there is no TTY** (so the default full run never hangs), and users can run it
  interactively with `docker compose run --rm -it scan … --stages 8`, or on the
  host. Force it with `email.linkedin2username.force: true`.
- **Detached report server** — AgentE never kills the gowitness report server; in
  a container the container is the lifecycle boundary. Stopping the container
  (`docker compose down` / `Ctrl-C`) frees port 7171.
- **No-timeout long runners** — bbot, nuclei, waymore, cloud_enum, pycroburst ship
  with `timeout: 0` by design; container runs can be long. Use `docker compose
  run` (foreground), not `up`.

## Phase 0 findings (to confirm on a clean host)

- **massdns**: puredns requires the `massdns` binary on PATH; without it Stage 2
  resolution fails. → built in the image + installed by CI native job + flagged in
  `install_tools.py --all` docs.
- **linkedin2username**: current wrapper runs interactively and waits for Enter at
  login (see `modules/email_enum.py`). Confirmed non-headless → auto-skip on no-TTY
  plus interactive/host fallback.

## Testing

- **Build test (CI)** — image builds on every PR.
- **Tool-presence test (CI)** — `--check-tools` exits non-zero if any required tool
  is missing (single most valuable regression guard against `@latest`/pip drift).
- **Smoke scan (per release)** — stages 1–5 + 10 against an owned domain; confirm
  `reports/index.html`, screenshots, and `:7171`.
- **Persistence test** — `./output/...` populated on host after exit.
- **Secret hygiene** — `docker history --no-trunc` shows no keys; `.env` git-ignored.
- **Native parity (CI)** — `install_tools.py --all` reaches the same pre-flight.

## Risks

| Risk | Mitigation |
|---|---|
| `@latest` drift breaks builds | Pinned versions; CI tool-presence test |
| massdns missed | Built in image; CI native job installs it |
| linkedin2username can't run headless | Auto-skip on no-TTY + interactive path |
| Image size (bbot/semgrep/chromium/templates) | Multi-stage + slim base + `.dockerignore`; optional "lite" image later |
| arm64 binaries unavailable | amd64-only publish for now; revisit multi-arch |
| Secrets baked in by accident | `.env` only; `.gitignore` + `.dockerignore`; CI hygiene check |

> This document is engineering guidance, not legal/compliance advice. Review any
> deployment that will process client engagement data against the relevant data-
> handling requirements before use.
