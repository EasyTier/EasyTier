#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

CORE_BIN=${CORE_BIN:-"$REPO_ROOT/target/debug/easytier-core"}
CLI_BIN=${CLI_BIN:-"$REPO_ROOT/target/debug/easytier-cli"}
TMPDIR_PATH=""
CORE_PID=""

print_section() {
  printf '\n==> %s\n' "$1"
}

print_output() {
  local title="$1"
  local content="$2"
  printf -- '---- %s ----\n' "$title"
  printf '%s\n' "$content"
  printf -- '---- end %s ----\n' "$title"
}

build_binaries() {
  print_section "Building easytier-core and easytier-cli"
  cargo build -p easytier --bin easytier-core --bin easytier-cli
}

ensure_binaries() {
  if [[ "${SKIP_BUILD:-0}" != "1" ]] || [[ ! -x "$CORE_BIN" ]] || [[ ! -x "$CLI_BIN" ]]; then
    build_binaries
  fi
}

make_tmpdir() {
  python - <<'PY'
import tempfile
print(tempfile.mkdtemp(prefix="easytier-cli-e2e-"))
PY
}

cleanup_tmpdir() {
  TMPDIR_TO_DELETE="$1" python - <<'PY'
import os
import shutil

shutil.rmtree(os.environ["TMPDIR_TO_DELETE"], ignore_errors=True)
PY
}

alloc_port() {
  python - <<'PY'
import socket

sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
}

wait_for_cli() {
  local rpc_port="$1"
  local attempts=0
  while (( attempts < 50 )); do
    if "$CLI_BIN" -p "127.0.0.1:${rpc_port}" -o json node >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 0.2
  done
  return 1
}

run_cmd() {
  local __var_name="$1"
  local title="$2"
  shift 2

  print_section "$title"
  printf '+'
  for arg in "$@"; do
    printf ' %q' "$arg"
  done
  printf '\n'

  local output
  if ! output=$("$@" 2>&1); then
    print_output "$title output" "$output"
    return 1
  fi

  print_output "$title output" "$output"
  printf -v "$__var_name" '%s' "$output"
}

assert_text_output() {
  local text_output="$1"
  grep -F '== e2e-inst-a (' <<<"$text_output" >/dev/null
  grep -F '== e2e-inst-b (' <<<"$text_output" >/dev/null
}

assert_multi_instance_json() {
  local json_payload="$1"
  JSON_PAYLOAD="$json_payload" python - <<'PY'
import json
import os

data = json.loads(os.environ["JSON_PAYLOAD"])
assert isinstance(data, list), data
assert len(data) == 2, data

names = {item["instance_name"] for item in data}
assert names == {"e2e-inst-a", "e2e-inst-b"}, names

for item in data:
    assert item["instance_id"], item
    assert isinstance(item["result"], dict), item
PY
}

assert_single_instance_json() {
  local json_payload="$1"
  JSON_PAYLOAD="$json_payload" python - <<'PY'
import json
import os

data = json.loads(os.environ["JSON_PAYLOAD"])
assert isinstance(data, dict), data
assert data["config"].find('instance_name = "e2e-inst-a"') >= 0, data["config"]
PY
}

assert_whitelist_fanout() {
  local json_payload="$1"
  JSON_PAYLOAD="$json_payload" python - <<'PY'
import json
import os

data = json.loads(os.environ["JSON_PAYLOAD"])
assert len(data) == 2, data
for item in data:
    assert item["result"]["tcp_ports"] == ["80", "443"], item
    assert item["result"]["udp_ports"] == [], item
PY
}

assert_single_instance_write() {
  local json_payload="$1"
  JSON_PAYLOAD="$json_payload" python - <<'PY'
import json
import os

data = {item["instance_name"]: item["result"] for item in json.loads(os.environ["JSON_PAYLOAD"])}
assert data["e2e-inst-a"]["tcp_ports"] == ["80", "443"], data
assert data["e2e-inst-b"]["tcp_ports"] == [], data
PY
}

main() {
  ensure_binaries

  TMPDIR_PATH=$(make_tmpdir)
  print_section "Created temporary test directory"
  printf '%s\n' "$TMPDIR_PATH"

  local rpc_port
  rpc_port=$(alloc_port)
  print_section "Allocated RPC port"
  printf '%s\n' "$rpc_port"

  cleanup() {
    if [[ -n "$CORE_PID" ]] && kill -0 "$CORE_PID" >/dev/null 2>&1; then
      kill "$CORE_PID" >/dev/null 2>&1 || true
      wait "$CORE_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "$TMPDIR_PATH" ]]; then
      cleanup_tmpdir "$TMPDIR_PATH"
    fi
  }
  trap cleanup EXIT

  cat >"$TMPDIR_PATH/inst-a.toml" <<'EOF'
instance_name = "e2e-inst-a"
listeners = []

[network_identity]
network_name = "e2e-net-a"
network_secret = ""

[flags]
no_tun = true
enable_ipv6 = false
EOF

  cat >"$TMPDIR_PATH/inst-b.toml" <<'EOF'
instance_name = "e2e-inst-b"
listeners = []

[network_identity]
network_name = "e2e-net-b"
network_secret = ""

[flags]
no_tun = true
enable_ipv6 = false
EOF

  "$CORE_BIN" --config-dir "$TMPDIR_PATH" --rpc-portal "127.0.0.1:${rpc_port}" \
    >"$TMPDIR_PATH/core.log" 2>&1 &
  CORE_PID=$!
  print_section "Started easytier-core"
  printf 'pid=%s\n' "$CORE_PID"

  wait_for_cli "$rpc_port"
  print_output "easytier-core startup log" "$(cat "$TMPDIR_PATH/core.log")"

  local text_output
  run_cmd text_output \
    "Case 1: node fanout in table mode" \
    "$CLI_BIN" -p "127.0.0.1:${rpc_port}" node
  assert_text_output "$text_output"

  local json_output
  run_cmd json_output \
    "Case 2: node fanout in JSON mode" \
    "$CLI_BIN" -p "127.0.0.1:${rpc_port}" -o json node
  assert_multi_instance_json "$json_output"

  local single_output
  run_cmd single_output \
    "Case 3: explicit instance selector stays single-instance" \
    "$CLI_BIN" -p "127.0.0.1:${rpc_port}" --instance-name e2e-inst-a -o json node
  assert_single_instance_json "$single_output"

  local set_whitelist_output
  run_cmd set_whitelist_output \
    "Case 4: whitelist set-tcp fans out to all instances" \
    "$CLI_BIN" -p "127.0.0.1:${rpc_port}" whitelist set-tcp 80,443

  local whitelist_output
  run_cmd whitelist_output \
    "Case 5: whitelist show confirms fanout write" \
    "$CLI_BIN" -p "127.0.0.1:${rpc_port}" -o json whitelist show
  assert_whitelist_fanout "$whitelist_output"

  local clear_whitelist_output
  run_cmd clear_whitelist_output \
    "Case 6: explicit selector write only touches one instance" \
    "$CLI_BIN" -p "127.0.0.1:${rpc_port}" --instance-name e2e-inst-b whitelist clear-tcp

  local cleared_output
  run_cmd cleared_output \
    "Case 7: whitelist show confirms single-instance write isolation" \
    "$CLI_BIN" -p "127.0.0.1:${rpc_port}" -o json whitelist show
  assert_single_instance_write "$cleared_output"

  print_section "Result"
  echo "CLI multi-instance E2E passed"
}

main "$@"
