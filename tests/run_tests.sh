#!/bin/bash
# Run all tests
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/.."

# Tests don't need inference latency; cap GLiNER/torch threads so a suite run
# doesn't light up every core (override by exporting EREBUS_GLINER_THREADS).
export EREBUS_GLINER_THREADS="${EREBUS_GLINER_THREADS:-2}"

# Isolate the suite from the real ~/.erebus. Fixture tokens that leak into the
# live Known-Value DB get detokenized into real files on AI write-backs
# (2026-06-10: leaked test placeholders silently corrupted three test files).
# Everything under ~/.erebus derives from Path.home(), so point HOME at a
# throwaway dir; keep the HF cache so GLiNER doesn't re-download the model.
REAL_HOME="$HOME"
export HF_HOME="${HF_HOME:-$REAL_HOME/.cache/huggingface}"
export HOME="$(mktemp -d -t erebus-tests)"
trap 'rm -rf "$HOME"' EXIT

echo "================================================"
echo "  erebus test suite"
echo "================================================"

python tests/test_pii_filter.py
python tests/test_file_guard_patterns.py
python tests/test_wrapper_integration.py
python tests/test_catalog_model.py
python tests/test_setup_services.py
python tests/test_daemon_lifecycle.py
python tests/test_shim_retokenize_gate.py
python tests/test_unresolved_block.py
python tests/test_detok_write_scope.py
python tests/test_batch_tokenize.py
python tests/test_token_usage.py
python tests/test_catalog_scan.py
python tests/test_catalog_matcher.py
python tests/test_catalog_cli.py
python tests/test_proxy_catalog_integration.py
python tests/test_catalog_api_e2e.py
python tests/test_proxy_tokenize_latency.py
python tests/test_check_file.py

echo ""
echo "=== Boundary Gateway Tests ==="
# Static FR-008 audit first: a boundary violation should fail the gate fast,
# before the per-module gateway loop runs.
python tests/audit_boundary.py
for t in tests/boundary/test_*.py; do
  [ -e "$t" ] || continue
  python "$t"
done

echo "================================================"
echo "  All tests done"
echo "================================================"
