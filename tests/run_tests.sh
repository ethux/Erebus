#!/bin/bash
# Run all tests
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/.."

echo "================================================"
echo "  erebus test suite"
echo "================================================"

python tests/test_pii_filter.py
python tests/test_file_guard_patterns.py
python tests/test_wrapper_integration.py

echo "================================================"
echo "  All tests done"
echo "================================================"
