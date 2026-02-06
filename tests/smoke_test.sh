#!/usr/bin/env bash
# Smoke test: pipe JSON to the hook and check output
set -euo pipefail

HOOK="python3 $(dirname "$0")/../permission-hook.py"
PASS=0
FAIL=0

check() {
    local desc="$1" input="$2" expected="$3"
    actual=$(echo "$input" | $HOOK)
    if echo "$actual" | grep -q "$expected"; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc"
        echo "    expected to contain: $expected"
        echo "    got: $actual"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Smoke Tests ==="

# Tier 1: auto-approve
check "Read safe file" \
    '{"tool_name":"Read","tool_input":{"file_path":"/app/main.py"},"cwd":"/app"}' \
    '"behavior": "allow"'

check "Bash git status" \
    '{"tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"/app"}' \
    '"behavior": "allow"'

# Tier 2: auto-deny
check "Bash rm -rf /" \
    '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"cwd":"/app"}' \
    '"behavior": "deny"'

check "Read .env" \
    '{"tool_name":"Read","tool_input":{"file_path":"/app/.env"},"cwd":"/app"}' \
    '"behavior": "deny"'

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
