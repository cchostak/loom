#!/usr/bin/env bash
# The guardrail is internal; test it inside its container, never republish it.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "${1:-}" == "--up" ]]; then
  make up
fi
# Retain --timeout compatibility with CI; Compose owns readiness waiting.
docker compose exec -T guardrail-proxy curl -fsS http://localhost:9090/health >/dev/null
python3 tests/gateway_security.py
python3 tests/telemetry_security.py
python3 tests/container_security.py
