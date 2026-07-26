#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    cat <<'EOF'
Usage: benchmark-two-node.sh BINARY {udp|tcp} [OUTPUT_DIR] [REPEATS] [SECONDS]

Runs two EasyTier cores in separate network namespaces and measures a
single iperf3 TCP flow in both directions. The underlay transport between
the EasyTier peers is selected by the second argument.

Environment:
  CORE_A_CPU          CPU for the listener core (default: 8)
  CORE_B_CPU          CPU for the connector core (default: 10)
  IPERF_SERVER_CPU    CPU for the iperf3 server (default: 12)
  IPERF_CLIENT_CPU    CPU for the iperf3 client (default: 14)
  IPERF_OMIT_SECONDS  Warm-up omitted by iperf3 (default: 2)
EOF
}

if [[ $# -lt 2 || $# -gt 5 ]]; then
    usage >&2
    exit 2
fi

if [[ ${EUID} -ne 0 ]]; then
    echo "benchmark must run as root" >&2
    exit 1
fi

binary=$(realpath "$1")
protocol=$2
output_dir=${3:-}
repeats=${4:-3}
duration=${5:-10}

case "$protocol" in
    udp | tcp) ;;
    *)
        echo "unsupported EasyTier transport: $protocol" >&2
        exit 2
        ;;
esac

if [[ ! -x "$binary" ]]; then
    echo "EasyTier binary is not executable: $binary" >&2
    exit 1
fi

for command in ip iperf3 jq taskset; do
    if ! command -v "$command" >/dev/null; then
        echo "required command is missing: $command" >&2
        exit 1
    fi
done

if [[ -z "$output_dir" ]]; then
    output_dir=$(mktemp -d "/tmp/easytier-two-node-${protocol}.XXXXXX")
elif [[ -e "$output_dir" ]]; then
    echo "output directory already exists: $output_dir" >&2
    exit 1
else
    mkdir -p "$output_dir"
fi
output_dir=$(realpath "$output_dir")

core_a_cpu=${CORE_A_CPU:-8}
core_b_cpu=${CORE_B_CPU:-10}
iperf_server_cpu=${IPERF_SERVER_CPU:-12}
iperf_client_cpu=${IPERF_CLIENT_CPU:-14}
omit_seconds=${IPERF_OMIT_SECONDS:-2}

namespace_a="etpa$$"
namespace_b="etpb$$"
veth_a="etva$$"
veth_b="etvb$$"
core_a_pid=
core_b_pid=
iperf_server_pid=

cleanup() {
    trap - EXIT INT TERM
    for pid in "$iperf_server_pid" "$core_b_pid" "$core_a_pid"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    ip netns delete "$namespace_b" 2>/dev/null || true
    ip netns delete "$namespace_a" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ip netns add "$namespace_a"
ip netns add "$namespace_b"
ip link add "$veth_a" type veth peer name "$veth_b"
ip link set "$veth_a" netns "$namespace_a"
ip link set "$veth_b" netns "$namespace_b"
ip -n "$namespace_a" link set lo up
ip -n "$namespace_b" link set lo up
ip -n "$namespace_a" addr add 198.18.0.1/24 dev "$veth_a"
ip -n "$namespace_b" addr add 198.18.0.2/24 dev "$veth_b"
ip -n "$namespace_a" link set "$veth_a" up
ip -n "$namespace_b" link set "$veth_b" up

common_args=(
    --network-name codex-perf
    --network-secret codex-perf
    --disable-p2p true
    --disable-tcp-hole-punching true
    --disable-udp-hole-punching true
    --disable-upnp true
    --disable-ipv6 true
    --multi-thread false
    --mtu 1360
    --console-log-level warn
)

ip netns exec "$namespace_a" taskset -c "$core_a_cpu" "$binary" \
    "${common_args[@]}" \
    --hostname perf-a \
    --instance-name perf-a \
    --ipv4 10.250.0.1 \
    --listeners "${protocol}://0.0.0.0:11010" \
    >"$output_dir/core-a.log" 2>&1 &
core_a_pid=$!

sleep 1

ip netns exec "$namespace_b" taskset -c "$core_b_cpu" "$binary" \
    "${common_args[@]}" \
    --hostname perf-b \
    --instance-name perf-b \
    --ipv4 10.250.0.2 \
    --no-listener \
    --peers "${protocol}://198.18.0.1:11010" \
    >"$output_dir/core-b.log" 2>&1 &
core_b_pid=$!

connected=false
for _ in $(seq 1 100); do
    if ip netns exec "$namespace_b" ping -c 1 -W 1 10.250.0.1 \
        >"$output_dir/ping.log" 2>&1; then
        connected=true
        break
    fi
    if ! kill -0 "$core_a_pid" 2>/dev/null ||
        ! kill -0 "$core_b_pid" 2>/dev/null; then
        echo "an EasyTier core exited before connectivity was established" >&2
        exit 1
    fi
    sleep 0.2
done

if [[ "$connected" != true ]]; then
    echo "EasyTier peers did not become reachable" >&2
    exit 1
fi

ip netns exec "$namespace_a" taskset -c "$iperf_server_cpu" iperf3 -s \
    >"$output_dir/iperf-server.log" 2>&1 &
iperf_server_pid=$!
sleep 0.5

ip netns exec "$namespace_b" taskset -c "$iperf_client_cpu" \
    iperf3 -c 10.250.0.1 -t 2 -O 1 --json \
    >"$output_dir/warmup.json"

for direction in forward reverse; do
    reverse_arg=()
    if [[ "$direction" == reverse ]]; then
        reverse_arg=(-R)
    fi
    for iteration in $(seq 1 "$repeats"); do
        ip netns exec "$namespace_b" taskset -c "$iperf_client_cpu" \
            iperf3 -c 10.250.0.1 \
            -t "$duration" \
            -O "$omit_seconds" \
            --json \
            "${reverse_arg[@]}" \
            >"$output_dir/${direction}-${iteration}.json"
    done
done

median_bps() {
    jq -s '
        map(.end.sum_received.bits_per_second) | sort |
        if length % 2 == 1 then
            .[length / 2 | floor]
        else
            (.[length / 2 - 1] + .[length / 2]) / 2
        end
    ' "$@"
}

forward_bps=$(median_bps "$output_dir"/forward-*.json)
reverse_bps=$(median_bps "$output_dir"/reverse-*.json)
jq -n \
    --arg binary "$binary" \
    --arg protocol "$protocol" \
    --argjson repeats "$repeats" \
    --argjson duration_seconds "$duration" \
    --argjson forward_bps "$forward_bps" \
    --argjson reverse_bps "$reverse_bps" \
    '{
        binary: $binary,
        peer_transport: $protocol,
        repeats: $repeats,
        duration_seconds: $duration_seconds,
        forward_bps: $forward_bps,
        reverse_bps: $reverse_bps,
        directional_median_bps: (($forward_bps + $reverse_bps) / 2)
    }' | tee "$output_dir/summary.json"

echo "results: $output_dir"
