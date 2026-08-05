#!/usr/bin/env bash
# Minimal aicontribcheck demo. Run from the project root.
#   bash examples/demo.sh
set -eu

fixture() {
    echo "--- $1 ---"
    python -m aicontribcheck "tests/fixtures/$1" || echo "(exit $?)"
    echo
}

fixture ban_repo
fixture allow_repo
fixture conditional_repo
fixture unknown_repo
fixture conflict_repo

echo "--- JSON output for conditional_repo ---"
python -m aicontribcheck --json tests/fixtures/conditional_repo
