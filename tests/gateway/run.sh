#!/bin/bash
# Run only the enterprise gateway tests, bypassing the full erebus/safechat suite.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/../.."

MODE="${1:-all}"
PG_DSN="${EREBUS_PG_DSN:-postgresql:///postgres}"

PURE_TESTS=(
  crypto
  rbac
  overload
  observability
  modalities
  residency
  no_antipatterns
  helpers_smoke
)

modules_missing() {
  local module
  local missing=()
  for module in "$@"; do
    if ! python -c "import ${module}" >/dev/null 2>&1; then
      missing+=("$module")
    fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "${missing[*]}"
    return 1
  fi
  return 0
}

require_modules() {
  local missing
  if ! missing="$(modules_missing "$@")"; then
    echo "Missing Python module(s): ${missing}" >&2
    echo "Install gateway deps with: python -m pip install -e '.[gateway]'" >&2
    exit 1
  fi
}

usage() {
  cat <<'EOF'
Usage: tests/gateway/run.sh [--all|--pure|--db]

  --all   Run pure gateway tests, then DB-backed gateway tests when Postgres is reachable.
  --pure  Run only no-Postgres/no-network gateway tests.
  --db    Require Postgres and run every tests/gateway/test_*.py file.

Set EREBUS_PG_DSN to choose the Postgres server, for example:
  EREBUS_PG_DSN=postgresql:///postgres tests/gateway/run.sh --db
EOF
}

case "$MODE" in
  --all|all) MODE="all" ;;
  --pure|pure) MODE="pure" ;;
  --db|db) MODE="db" ;;
  -h|--help|help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

run_pure() {
  require_modules cryptography
  echo ""
  echo "=== Gateway pure tests (no Postgres/network) ==="
  for name in "${PURE_TESTS[@]}"; do
    python "tests/gateway/test_${name}.py"
  done
}

postgres_ready() {
  python -c "import psycopg, os; psycopg.connect(os.environ.get('EREBUS_PG_DSN','postgresql:///postgres')).close()"
}

run_db() {
  echo ""
  echo "=== Gateway DB-backed tests (maintenance DSN=${PG_DSN}) ==="
  local missing
  if ! missing="$(modules_missing cryptography fastapi psycopg psycopg_pool)"; then
    if [ "$MODE" = "db" ]; then
      echo "Missing Python module(s): ${missing}" >&2
      echo "Install gateway deps with: python -m pip install -e '.[gateway]'" >&2
      exit 1
    fi
    echo "  (skipped: missing Python module(s): ${missing})"
    return
  fi

  if ! postgres_ready >/dev/null 2>&1; then
    if [ "$MODE" = "db" ]; then
      echo "PostgreSQL is required for --db but is not reachable at ${PG_DSN}" >&2
      exit 1
    fi
    echo "  (skipped: psycopg + a reachable PostgreSQL required)"
    return
  fi

  # Release gate: give each test its own pristine database so nothing self-skips
  # (a missing named DB would otherwise skip silently) and the subset-applying
  # tests cannot pollute one another. Hard-fail if any test fails. The network-level
  # end-to-end acceptance (tests/gateway/e2e/test_*.py; FR-014/SC-002/SC-007) is a
  # NON-skipping part of this gate: it runs a real uvicorn + a mock provider against a
  # fresh DB exactly like the per-module tests, so token-only egress and restoration are
  # verified over the wire before release.
  local failed=0 t name db dsn
  for t in tests/gateway/test_*.py tests/gateway/e2e/test_*.py; do
    [ -e "$t" ] || continue
    name="$(basename "$t" .py)"
    db="erebus_gate_${name}"
    if ! dsn="$(python tests/gateway/_dbgate.py create "$PG_DSN" "$db")"; then
      echo "  could not provision database ${db}" >&2
      exit 1
    fi
    if ! EREBUS_PG_DSN="$dsn" python "$t"; then
      failed=1
    fi
    python tests/gateway/_dbgate.py drop "$PG_DSN" "$db" >/dev/null 2>&1 || true
  done
  if [ "$failed" -ne 0 ]; then
    echo "gateway release gate: one or more tests FAILED" >&2
    exit 1
  fi
}

echo "================================================"
echo "  enterprise gateway test suite"
echo "================================================"

case "$MODE" in
  pure) run_pure ;;
  db) run_db ;;
  all) run_pure; run_db ;;
esac

echo "================================================"
echo "  Gateway tests done"
echo "================================================"
