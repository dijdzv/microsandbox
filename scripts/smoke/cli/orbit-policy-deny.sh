#!/usr/bin/env bash
# Isolated KVM smoke test for Orbit's policy-deny JSONL contract.
# Usage: orbit-policy-deny.sh <patched-msb> <libkrunfw-dir> <alpine-image-tar> <agentd>
set -euo pipefail

binary=${1:?patched msb binary required}
firmware_dir=${2:?libkrunfw directory required}
image_tar=${3:?Alpine image archive required}
agentd=${4:?guest agentd binary required}
[[ -x "$binary" && -f "$firmware_dir/libkrunfw.so.5.6.1" && -f "$image_tar" && -x "$agentd" ]]

test_dir=$(mktemp -d /tmp/msb-orbit-deny.XXXXXX)
mkdir -p "$test_dir/bin" "$test_dir/lib" "$test_dir/home"
cp "$binary" "$test_dir/bin/msb"
cp -a "$firmware_dir"/. "$test_dir/lib/"
msb="$test_dir/bin/msb"
export MSB_HOME="$test_dir/home"
export LD_LIBRARY_PATH="$test_dir/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export MSB_AGENTD_PATH="$agentd"
name="orbit-deny-smoke-$$"
second_name="orbit-deny-isolation-$$"

cleanup() {
  local result=$?
  trap - EXIT
  set +e
  "$msb" stop "$name" >/dev/null 2>&1
  "$msb" stop "$second_name" >/dev/null 2>&1
  if [[ $result -eq 0 ]]; then
    "$msb" remove "$name" >/dev/null 2>&1
    "$msb" remove "$second_name" >/dev/null 2>&1
    gio trash "$test_dir" || printf 'test data retained: %s\n' "$test_dir" >&2
  else
    printf 'test failed; isolated diagnostics retained: %s\n' "$test_dir" >&2
  fi
  exit "$result"
}
trap cleanup EXIT

"$msb" image load -q -t alpine -i "$image_tar"
if capture_error=$(MSB_DENY_LOG_PATH="$test_dir/missing/deny.jsonl" "$msb" ls 2>&1); then
  printf 'capture-open failure unexpectedly succeeded\n' >&2
  exit 1
fi
[[ "$capture_error" == *"policy-deny capture unavailable"* ]]
MSB_DENY_LOG_PATH="$test_dir/deny.jsonl" "$msb" create \
  --name "$name" --memory 512M --cpus 1 --max-duration 2m \
  --no-net alpine

"$msb" exec --no-tty --timeout 30s "$name" -- /bin/sh -c '
  nslookup blocked.example >/dev/null 2>&1 || true
  wget -T 2 -O - http://198.51.100.42:80/ >/dev/null 2>&1 || true
  printf probe | nc -u -w 1 198.51.100.42 12345 >/dev/null 2>&1 || true
  gateway=$(ip route | awk '\''/^default via/ {print $3; exit}'\'')
  ping -c 1 -W 1 "$gateway" >/dev/null 2>&1 || true
'

jq -es '
  all(.[]; .target == "policy_deny" and .fields.sandbox_id != "" and
      (.fields.host | type) == "string" and (.fields.ip | type) == "string" and
      (.fields.policy_origin | IN("tenant", "platform"))) and
  ([.[].fields.sandbox_id] | unique | length == 1) and
  ([.[].fields.transport] | index("dns") != null and index("tcp") != null and
    index("udp") != null and index("icmpv4") != null)
' "$test_dir/deny.jsonl"

# Two concurrent VMs must not write into one another's capture file.
MSB_DENY_LOG_PATH="$test_dir/deny-second.jsonl" "$msb" create \
  --name "$second_name" --memory 512M --cpus 1 --max-duration 2m \
  --no-net alpine
"$msb" exec --no-tty --timeout 15s "$second_name" -- /bin/sh -c \
  'wget -T 2 -O - http://203.0.113.55:80/ >/dev/null 2>&1 || true'
jq -es 'length > 0 and all(.[]; .target == "policy_deny") and
  ([.[].fields.sandbox_id] | unique | length == 1)' "$test_dir/deny-second.jsonl"
first_id=$(jq -r '.fields.sandbox_id' "$test_dir/deny.jsonl" | head -1)
second_id=$(jq -r '.fields.sandbox_id' "$test_dir/deny-second.jsonl" | head -1)
[[ -n "$first_id" && -n "$second_id" && "$first_id" != "$second_id" ]]
jq -es --arg ip '203.0.113.55' 'all(.[]; .fields.ip != $ip)' "$test_dir/deny.jsonl"

printf 'policy-deny JSONL passed: %s + %s isolated events\n' \
  "$(wc -l < "$test_dir/deny.jsonl")" "$(wc -l < "$test_dir/deny-second.jsonl")"
