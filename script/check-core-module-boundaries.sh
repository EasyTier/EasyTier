#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

fail_if_match() {
    local label=$1
    local pattern=$2
    shift 2

    local output
    local status
    set +e
    output=$(rg --line-number --pcre2 --multiline "$pattern" "$@")
    status=$?
    set -e

    if [[ $status -eq 0 ]]; then
        echo "module boundary violation: $label" >&2
        echo "$output" >&2
        return 1
    fi
    if [[ $status -ne 1 ]]; then
        echo "module boundary check failed while scanning: $label" >&2
        return "$status"
    fi
}

forbid_modules() {
    local label=$1
    local modules=$2
    shift 2

    fail_if_match \
        "$label (qualified path)" \
        "crate::(?:${modules})::" \
        "$@"
    fail_if_match \
        "$label (crate use tree)" \
        "(?ms)^(?<indent>[ \\t]*)use\\s+crate::\\{(?:[ \\t]*(?:${modules})(?:::|,)|[^;]*?^\\k<indent>[ \\t]{4}(?:${modules})(?:::|,))" \
        "$@"
}

rust_roots=(
    easytier-core/src
    easytier/src
    easytier-web/src
    easytier-gui/src-tauri/src
    easytier-contrib
)

legacy_path_patterns=(
    'listener::SocketListener'
    'rpc_impl'
    'rpc::metrics'
    'foundation::compressor'
    'peers::context::(?:Arc)?ByteLimiter'
    'gateway::config::'
    'gateway::proxy::ProxyRuntimeConfig'
    '(?<!config::)gateway::(?:GatewayRuntimeConfig|PortForwardConfig)'
    'gateway::(?:stack|tokio_smoltcp)'
    'connectivity::hole_punch::udp::(?:HOLE_PUNCH_PACKET_BODY_LEN|hole_punch_packet_tid|new_hole_punch_packet)'
    'socket::host::'
)
legacy_path_pattern=$(IFS='|'; printf '%s' "${legacy_path_patterns[*]}")

fail_if_match \
    "legacy core module path" \
    "$legacy_path_pattern" \
    --glob '*.rs' \
    "${rust_roots[@]}"

fail_if_match \
    "gateway implementation module is externally visible" \
    '^pub(?:\(crate\))? mod (?:module|smoltcp|socks5);' \
    easytier-core/src/gateway/mod.rs

fail_if_match \
    "hole-punch engine module is externally visible" \
    '^pub mod (?:tcp|udp);' \
    easytier-core/src/connectivity/hole_punch/mod.rs

forbid_modules \
    "foundation depends on a domain module" \
    'config|packet|socket|host|tunnel|listener|connectivity|peers|rpc|gateway|instance' \
    --glob '*.rs' \
    easytier-core/src/foundation

forbid_modules \
    "packet depends above the wire-format layer" \
    'socket|host|tunnel|listener|connectivity|peers|rpc|gateway|instance' \
    --glob '*.rs' \
    easytier-core/src/packet

forbid_modules \
    "socket production code depends on a higher layer" \
    'host|tunnel|listener|connectivity|peers|rpc|gateway|instance' \
    --glob '*.rs' \
    --glob '!**/tests.rs' \
    easytier-core/src/socket

forbid_modules \
    "host depends above the host seam" \
    'tunnel|listener|connectivity|peers|rpc|gateway|instance' \
    --glob '*.rs' \
    easytier-core/src/host

forbid_modules \
    "config reaches into gateway or instance" \
    'gateway|instance' \
    --glob '*.rs' \
    easytier-core/src/config

forbid_modules \
    "listener reaches into peer, RPC, gateway, or instance domains" \
    'peers|rpc|gateway|instance' \
    --glob '*.rs' \
    easytier-core/src/listener

forbid_modules \
    "connectivity reaches into gateway or instance" \
    'gateway|instance' \
    --glob '*.rs' \
    easytier-core/src/connectivity

forbid_modules \
    "peer or RPC code reaches into gateway or instance" \
    'gateway|instance' \
    --glob '*.rs' \
    easytier-core/src/peers \
    easytier-core/src/rpc

forbid_modules \
    "gateway reaches into the composition root" \
    'instance' \
    --glob '*.rs' \
    easytier-core/src/gateway

obsolete_paths=(
    easytier-core/src/foundation/compressor.rs
    easytier-core/src/gateway/stack.rs
    easytier-core/src/gateway/tokio_smoltcp
    easytier-core/src/connectivity/hole_punch/udp/packet.rs
    easytier-core/src/rpc/metrics.rs
)

for path in "${obsolete_paths[@]}"; do
    if [[ -e $path ]]; then
        echo "module boundary violation: obsolete path still exists: $path" >&2
        exit 1
    fi
done

required_paths=(
    easytier-core/src/gateway/smoltcp/mod.rs
    easytier-core/src/packet/hole_punch.rs
)

for path in "${required_paths[@]}"; do
    if [[ ! -f $path ]]; then
        echo "module boundary violation: required path is missing: $path" >&2
        exit 1
    fi
done

echo "core module boundaries: ok"
