#!/usr/bin/env sh
# AgentE container entrypoint.
#
# Forwards all arguments to the orchestrator, so:
#   docker run agente --check-tools
#   docker run agente -d example.com -c "Acme Corp"
#   docker compose run --rm scan -d example.com --stages 1,2,3
#
# With no arguments the image's CMD supplies --check-tools (a safe no-op that
# proves every tool resolves).
set -eu
exec python orchestrator.py "$@"
