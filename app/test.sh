#!/bin/zsh
set -euo pipefail
cd "${0:A:h}"
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/vpn-status-tests.XXXXXX")
trap 'rm -f "$test_dir/status-tests"; rmdir "$test_dir"' EXIT
xcrun swiftc Status.swift tests/status_tests.swift -o "$test_dir/status-tests"
"$test_dir/status-tests"
