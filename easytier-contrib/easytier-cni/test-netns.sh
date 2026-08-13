#!/usr/bin/env bash
set -euo pipefail

[[ $EUID -eq 0 ]] || {
    echo "easytier-cni netns test requires root" >&2
    exit 2
}

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
core=${1:-$repo_root/target/debug/easytier-core}
cni=${2:-$repo_root/target/debug/easytier-cni}
for executable in "$core" "$cni"; do
    [[ -x $executable ]] || {
        echo "required executable is unavailable: $executable" >&2
        exit 2
    }
done
for command in ip jq mktemp timeout; do
    command -v "$command" >/dev/null || {
        echo "$command is required" >&2
        exit 2
    }
done
[[ -c /dev/net/tun ]] || {
    echo "/dev/net/tun is unavailable" >&2
    exit 2
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/easytier-cni-netns.XXXXXX")
netns="et-cni-${BASHPID}"
relay_port=$((21000 + BASHPID % 1000))
relay_rpc_port=$((22000 + BASHPID % 1000))
daemon_rpc_socket=$tmp/rpc.sock
relay_pid=
daemon_pid=

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    set +e
    [[ -z $daemon_pid ]] || kill "$daemon_pid" 2>/dev/null
    [[ -z $relay_pid ]] || kill "$relay_pid" 2>/dev/null
    [[ -z $daemon_pid ]] || wait "$daemon_pid" 2>/dev/null
    [[ -z $relay_pid ]] || wait "$relay_pid" 2>/dev/null
    ip netns delete "$netns" 2>/dev/null
    if [[ $status -ne 0 ]]; then
        if [[ -s $tmp/result.json ]]; then
            echo "CNI result:" >&2
            sed 's/^/  /' "$tmp/result.json" >&2
        fi
        echo "relay log:" >&2
        sed 's/^/  /' "$tmp/relay.log" >&2 2>/dev/null || true
        echo "daemon log:" >&2
        sed 's/^/  /' "$tmp/daemon.log" >&2 2>/dev/null || true
    fi
    rm -rf "$tmp"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 0700 "$tmp/configs" "$tmp/cni-bin"
printf '%s\n' 'integration-secret' >"$tmp/network-secret"
chmod 0600 "$tmp/network-secret"

cat >"$tmp/cni-bin/test-ipam" <<'EOF'
#!/bin/sh
set -eu
case ${CNI_COMMAND:?} in
    ADD)
        printf '%s\n' '{"cniVersion":"1.0.0","ips":[{"address":"10.200.0.10/24"}]}'
        ;;
    DEL|CHECK|STATUS)
        ;;
    *)
        exit 1
        ;;
esac
EOF
chmod 0755 "$tmp/cni-bin/test-ipam"

ip netns add "$netns"
ip -n "$netns" link set lo up

"$core" \
    --network-name cni-integration \
    --network-secret integration-secret \
    --no-tun true \
    --listeners "tcp://127.0.0.1:$relay_port" \
    --rpc-portal "127.0.0.1:$relay_rpc_port" \
    --disable-ipv6 true \
    --console-log-level info >"$tmp/relay.log" 2>&1 &
relay_pid=$!

umask 077
"$core" \
    --daemon \
    --config-dir "$tmp/configs" \
    --rpc-portal "unix://$daemon_rpc_socket" \
    --console-log-level info >"$tmp/daemon.log" 2>&1 &
daemon_pid=$!

for _ in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$relay_rpc_port") 2>/dev/null &&
       [[ -S $daemon_rpc_socket ]]; then
        break
    fi
    sleep 0.1
done
kill -0 "$relay_pid"
kill -0 "$daemon_pid"

cat >"$tmp/config.json" <<EOF
{
  "cniVersion": "1.0.0",
  "name": "easytier-integration",
  "type": "easytier-cni",
  "rpcPortal": "unix://$daemon_rpc_socket",
  "networkName": "cni-integration",
  "networkSecretFile": "$tmp/network-secret",
  "peers": ["tcp://127.0.0.1:$relay_port"],
  "mtu": 1380,
  "timeoutSeconds": 20,
  "ipam": {"type": "test-ipam"}
}
EOF

run_cni() {
    local command=$1
    local config=$2
    CNI_COMMAND=$command \
    CNI_CONTAINERID=integration-container \
    CNI_NETNS="/var/run/netns/$netns" \
    CNI_IFNAME=net1 \
    CNI_PATH="$tmp/cni-bin" \
        timeout 30s "$cni" <"$config"
}

run_cni ADD "$tmp/config.json" >"$tmp/result.json"
jq -e '.interfaces[0].name == "net1" and .ips[0].address == "10.200.0.10/24"' \
    "$tmp/result.json" >/dev/null
ip -n "$netns" link show net1 >/dev/null
ip -n "$netns" -4 address show dev net1 | grep -F '10.200.0.10/24' >/dev/null

jq --slurpfile result "$tmp/result.json" '. + {prevResult: $result[0]}' \
    "$tmp/config.json" >"$tmp/check.json"
run_cni CHECK "$tmp/check.json"
run_cni DEL "$tmp/check.json"
if ip -n "$netns" link show net1 >/dev/null 2>&1; then
    echo "EasyTier TUN remains after DEL" >&2
    exit 1
fi
[[ -z $(find "$tmp/configs" -maxdepth 1 -name '*.toml' -print -quit) ]]

ip netns delete "$netns"
run_cni DEL "$tmp/check.json"

echo "EasyTier CNI netns integration passed"
