#!/bin/bash
# Build the gateway image, start it with Postgres, and check it serves.
# CI runs this before publishing. Uses its own env file so a real gateway.env is never touched.
set -euo pipefail
cd "$(dirname "$0")/.."

SMOKE_ENV=".smoke.env"
export EREBUS_ENV_FILE="../${SMOKE_ENV}"
export EREBUS_IMAGE="erebus-gateway:smoke"
# Own compose project: `down -v` must never touch a real stack started from the same file.
compose() { docker compose -p erebus-smoke -f deploy/docker-compose.yml "$@"; }
trap 'compose down -v >/dev/null 2>&1 || true; rm -f "$SMOKE_ENV"' EXIT

KEY="$(python3 -c 'import base64,secrets;print(base64.b64encode(secrets.token_bytes(32)).decode())')"
sed -e "s|^EREBUS_GATEWAY_MASTER_KEY=.*|EREBUS_GATEWAY_MASTER_KEY=${KEY}|" deploy/gateway.env.example > "$SMOKE_ENV"
echo "EREBUS_DISABLE_GLINER=1" >> "$SMOKE_ENV"

compose build
# Migrations ship as package data; without them a fresh database never gets its tables.
# -w /tmp: import the installed package, not the /app source copy the entrypoint never sees.
docker run --rm -w /tmp --entrypoint python "$EREBUS_IMAGE" -c \
  'import pathlib, erebus.gateway as g; n = len(list((pathlib.Path(g.__file__).parent / "schema").glob("*.sql"))); print(f"{n} migrations in image"); raise SystemExit(n == 0)'
compose up -d --wait
curl -fsS http://localhost:8080/readyz
echo
curl -fsS http://localhost:8080/v1/license | grep -q '"status":"none"'
docker run --rm --entrypoint sh "$EREBUS_IMAGE" -c \
  'for p in /app/gateway.env /app/.smoke.env /app/.git /app/.venv /app/specs; do [ ! -e "$p" ] || { echo "leaked into image: $p"; exit 1; }; done'
echo "smoke OK"
