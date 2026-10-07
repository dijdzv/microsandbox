#!/usr/bin/env bash
# No-VM regression for Orbit's fail-closed deny capture startup contract.
# Usage: bash orbit-deny-capture-open.sh <msb>
set -euo pipefail

binary=${1:?msb binary required}
[[ -x "$binary" ]]
test_dir=$(mktemp -d /tmp/msb-orbit-capture-open.XXXXXX)
mkdir -p "$test_dir/home"
trap 'printf "isolated capture fixture: %s\n" "$test_dir" >&2' EXIT

if capture_error=$(MSB_HOME="$test_dir/home" \
  MSB_DENY_LOG_PATH="$test_dir/missing/deny.jsonl" \
  "$binary" list --format json 2>&1); then
  printf 'capture-open failure unexpectedly succeeded\n' >&2
  exit 1
fi
[[ "$capture_error" == *"policy-deny capture unavailable"* ]]

MSB_HOME="$test_dir/home" MSB_DENY_LOG_PATH="$test_dir/deny.jsonl" \
  "$binary" list --format json >/dev/null
[[ -f "$test_dir/deny.jsonl" ]]
[[ $(stat -c '%a' "$test_dir/deny.jsonl") == 600 ]]
printf 'deny capture startup rejection and private file passed\n'
