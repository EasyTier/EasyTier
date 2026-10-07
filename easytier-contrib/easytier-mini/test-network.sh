#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    printf 'usage: %s MINI_BINARY [PEER_BINARY]\n' "$0"
    printf '%s\n' \
        'Run as root on Linux with TUN and network-namespace support.' \
        'PEER_BINARY defaults to MINI_BINARY; an upstream mini tests interoperability.' \
        'ET_MINI_TEST_TIMEOUT sets each readiness deadline in seconds (default: 60).' \
        'ET_MINI_TEST_IPV6=1 also checks static IPv6 over TCP/UDP (default: off).' \
        'ET_MINI_TEST_SKIP_DHCP=1 skips the DHCP case for static-only builds (default: off).' \
        'ET_MINI_TEST_KEEP_LOGS=1 preserves temporary configs and logs after success.'
}

fail() {
    printf 'FAIL case=%s message=%s\n' "${current_case:-setup}" "$*" >&2
    exit 1
}

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
    usage
    exit 0
fi
if (( $# < 1 || $# > 2 )); then
    usage >&2
    exit 2
fi
[[ $(uname -s) == Linux ]] || fail 'Linux is required'
(( EUID == 0 )) || fail 'root is required for isolated network namespaces'
[[ -c /dev/net/tun ]] || fail '/dev/net/tun is unavailable'
for command in ip ping timeout awk mktemp readlink cmp; do
    command -v "$command" >/dev/null || fail "missing command: $command"
done

test_timeout=${ET_MINI_TEST_TIMEOUT:-60}
[[ $test_timeout =~ ^[1-9][0-9]*$ ]] || fail 'ET_MINI_TEST_TIMEOUT must be a positive integer'
test_ipv6=${ET_MINI_TEST_IPV6:-0}
[[ $test_ipv6 == 0 || $test_ipv6 == 1 ]] || fail 'ET_MINI_TEST_IPV6 must be 0 or 1'
skip_dhcp=${ET_MINI_TEST_SKIP_DHCP:-0}
[[ $skip_dhcp == 0 || $skip_dhcp == 1 ]] || fail 'ET_MINI_TEST_SKIP_DHCP must be 0 or 1'
mini=$(readlink -f -- "$1")
peer=$(readlink -f -- "${2:-$1}")
[[ -x $mini ]] || fail "mini binary is not executable: $mini"
[[ -x $peer ]] || fail "peer binary is not executable: $peer"

workdir=$(mktemp -d "${TMPDIR:-/tmp}/easytier-mini-net.XXXXXXXX")
prefix="etmn-$$-$RANDOM"
ns_a="$prefix-a"
ns_b="$prefix-b"
ns_c="$prefix-c"
secret="$prefix-$RANDOM-$RANDOM"
namespaces=()
node_pids=()
node_labels=()
child_pids=()
current_case=setup

namespace_pids() {
    local ns
    for ns in "${namespaces[@]}"; do
        ip netns pids "$ns" 2>/dev/null || true
    done
}

stop_nodes() {
    local pid deadline
    local -a pids
    mapfile -t pids < <(namespace_pids)
    for pid in "${pids[@]}"; do
        [[ $pid =~ ^[0-9]+$ ]] && kill -TERM "$pid" 2>/dev/null || true
    done
    deadline=$((SECONDS + 5))
    while (( SECONDS < deadline )); do
        mapfile -t pids < <(namespace_pids)
        (( ${#pids[@]} == 0 )) && break
        sleep 0.2
    done
    mapfile -t pids < <(namespace_pids)
    for pid in "${pids[@]}"; do
        [[ $pid =~ ^[0-9]+$ ]] && kill -KILL "$pid" 2>/dev/null || true
    done
    for pid in "${child_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    node_pids=()
    node_labels=()
    child_pids=()
}

cleanup() {
    local status=$1 ns logfile
    trap - EXIT
    set +e
    stop_nodes
    for ns in "${namespaces[@]}"; do
        ip netns delete "$ns"
    done
    if (( status != 0 )); then
        for logfile in "$workdir"/*.log; do
            [[ -f $logfile ]] || continue
            printf '\n--- %s ---\n' "$(basename "$logfile")" >&2
            tail -n 35 "$logfile" >&2
        done
    fi
    if (( status != 0 )) || [[ ${ET_MINI_TEST_KEEP_LOGS:-0} == 1 ]]; then
        printf 'LOGS path=%s\n' "$workdir" >&2
    else
        rm -rf -- "$workdir"
    fi
    exit "$status"
}
trap 'cleanup $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

create_namespace() {
    ip netns add "$1"
    namespaces+=("$1")
    ip -n "$1" link set lo up
}

create_link() {
    local left=$1 left_dev=$2 left_ip=$3 right=$4 right_dev=$5 right_ip=$6
    ip -n "$left" link add "$left_dev" type veth peer name "$right_dev" netns "$right"
    ip -n "$left" address add "$left_ip/30" dev "$left_dev"
    ip -n "$right" address add "$right_ip/30" dev "$right_dev"
    ip -n "$left" link set "$left_dev" up
    ip -n "$right" link set "$right_dev" up
}

assert_nodes_running() {
    local index
    for index in "${!node_pids[@]}"; do
        kill -0 "${node_pids[$index]}" 2>/dev/null ||
            fail "node exited: ${node_labels[$index]}"
    done
}

wait_for() {
    local description=$1 deadline=$((SECONDS + test_timeout))
    shift
    until "$@"; do
        assert_nodes_running
        (( SECONDS < deadline )) || fail "deadline exceeded: $description"
        sleep 0.2
    done
    assert_nodes_running
}

write_config() {
    local filename=$1 label=$2 addressing=$3 transport=$4 peer_uri=${5:-} ipv6=${6:-}
    {
        printf 'instance_name = "%s"\nhostname = "%s"\n' "$label" "$label"
        if [[ $addressing == dhcp ]]; then
            printf 'dhcp = true\n'
        else
            printf 'ipv4 = "%s/24"\n' "$addressing"
        fi
        if [[ -n $ipv6 ]]; then
            printf 'ipv6 = "%s/64"\n' "$ipv6"
        fi
        printf 'listeners = ["%s://0.0.0.0:11010"]\n' "$transport"
        printf 'stun_servers = []\nstun_servers_v6 = []\ntcp_stun_servers = []\n'
        printf '\n[network_identity]\nnetwork_name = "%s-%s"\nnetwork_secret = "%s"\n' \
            "$prefix" "$current_case" "$secret"
        if [[ -n $peer_uri ]]; then
            printf '\n[[peer]]\nuri = "%s"\n' "$peer_uri"
        fi
        printf '%s\n' \
            '' '[flags]' 'dev_name = "mini0"' 'enable_encryption = true' \
            'disable_p2p = true' 'disable_udp_hole_punching = true'
    } >"$filename"
}

start_node() {
    local ns=$1 binary=$2 config=$3 label=$4
    ip netns exec "$ns" "$binary" -c "$config" >"$workdir/$current_case-$label.log" 2>&1 &
    node_pids+=("$!")
    node_labels+=("$label")
    child_pids+=("$!")
    printf 'NODE case=%s node=%s pid=%s\n' "$current_case" "$label" "$!"
}

tun_ipv4() {
    ip -n "$1" -4 -o address show dev mini0 2>/dev/null |
        awk '$3 == "inet" { split($4, address, "/"); print address[1]; exit }'
}

has_tun_ipv4() {
    [[ $(tun_ipv4 "$1") == "$2" ]]
}

has_tun_ipv6() {
    ip -n "$1" -6 -o address show dev mini0 scope global 2>/dev/null |
        awk -v wanted="$2/64" '$3 == "inet6" && $4 == wanted { found = 1 }
            END { exit !found }'
}

ping_once() {
    ip netns exec "$1" ping -n -I mini0 -c 1 -W 1 "$2" >/dev/null 2>&1
}

check_ping() {
    wait_for "TUN ping $1 -> $2" ping_once "$1" "$2"
    ip netns exec "$1" ping -n -I mini0 -c 3 -W 2 "$2" >"$workdir/$current_case-ping-${1##*-}-$2.log"
    printf 'PASS case=%s check=ping from=%s target=%s\n' "$current_case" "${1##*-}" "$2"
}

ping_ipv6_once() {
    ip netns exec "$1" ping -6 -n -I mini0 -c 1 -W 1 "$2" >/dev/null 2>&1
}

check_ping_ipv6() {
    wait_for "IPv6 TUN ping $1 -> $2" ping_ipv6_once "$1" "$2"
    ip netns exec "$1" ping -6 -n -I mini0 -c 3 -W 2 "$2" \
        >"$workdir/$current_case-ping6-${1##*-}-$2.log"
    printf 'PASS case=%s check=ping family=ipv6 from=%s target=%s\n' \
        "$current_case" "${1##*-}" "$2"
}

sample_metrics() {
    local index pid values
    # This is a defined quiet sampling interval, not a performance benchmark.
    sleep 2
    assert_nodes_running
    for index in "${!node_pids[@]}"; do
        pid=${node_pids[$index]}
        values=$(awk '
            /^VmRSS:/ { rss = $2 }
            /^Threads:/ { threads = $2 }
            END { printf "rss_kib=%s threads=%s", rss ? rss : "NA", threads ? threads : "NA" }
        ' "/proc/$pid/status")
        printf 'METRIC case=%s node=%s pid=%s idle_seconds=2 %s\n' \
            "$current_case" "${node_labels[$index]}" "$pid" "$values"
    done
}

payload_backend=none
if command -v python3 >/dev/null; then
    payload_backend=python3
    cat >"$workdir/payload.py" <<'PY'
import pathlib
import socket
import sys

mode, transport, address, port, deadline, ready = sys.argv[1:]
port, deadline = int(port), int(deadline)
payload = bytes(range(256)) * 256 if transport == "tcp" else bytes(range(240)) * 5
kind = socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM
family = socket.AF_INET6 if ":" in address else socket.AF_INET
with socket.socket(family, kind) as sock:
    sock.settimeout(deadline)
    if mode == "server":
        sock.bind((address, port))
        if transport == "tcp":
            sock.listen(1)
        pathlib.Path(ready).touch()
        if transport == "tcp":
            connection, _ = sock.accept()
            with connection:
                connection.settimeout(deadline)
                received = bytearray()
                while True:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
                if received != payload:
                    raise RuntimeError("TCP payload mismatch")
                connection.sendall(received)
        else:
            received, source = sock.recvfrom(65536)
            if received != payload:
                raise RuntimeError("UDP payload mismatch")
            sock.sendto(received, source)
    elif transport == "tcp":
        sock.connect((address, port))
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        received = bytearray()
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            received.extend(chunk)
        if received != payload:
            raise RuntimeError("TCP echo mismatch")
    else:
        sock.connect((address, port))
        sock.send(payload)
        if sock.recv(65536) != payload:
            raise RuntimeError("UDP echo mismatch")
PY
elif command -v nc >/dev/null; then
    payload_backend=netcat
else
    printf 'SKIP check=payload reason=python3-and-netcat-unavailable\n'
fi

python_server_ready() {
    kill -0 "$1" 2>/dev/null || fail 'payload server exited before binding'
    [[ -f $2 ]]
}

netcat_server_ready() {
    local ns=$1 transport=$2 pid=$3
    kill -0 "$pid" 2>/dev/null || fail 'netcat server exited before binding'
    ip netns exec "$ns" awk '
        $2 ~ /:7D01$/ { found = 1 }
        END { exit !found }
    ' "/proc/net/$transport"
}

check_payload() {
    local source=$1 target_ns=$2 target_ip=$3 transport ready server_pid status expected received
    local payload_case="$current_case" family_field=
    if [[ $target_ip == *:* ]]; then
        if [[ $payload_backend != python3 ]]; then
            printf 'SKIP case=%s check=payload family=ipv6 reason=python3-unavailable\n' "$current_case"
            return 0
        fi
        payload_case="$current_case-ipv6"
        family_field=' family=ipv6'
    fi
    [[ $payload_backend != none ]] || return 0
    for transport in tcp udp; do
        ready="$workdir/$payload_case-$transport.ready"
        if [[ $payload_backend == python3 ]]; then
            ip netns exec "$target_ns" timeout --kill-after=2 "$test_timeout" \
                python3 "$workdir/payload.py" server "$transport" "$target_ip" 32001 "$test_timeout" "$ready" \
                >"$workdir/$payload_case-$transport-server.log" 2>&1 &
            server_pid=$!
            child_pids+=("$server_pid")
            wait_for "$transport payload server" python_server_ready "$server_pid" "$ready"
            ip netns exec "$source" timeout --kill-after=2 "$test_timeout" \
                python3 "$workdir/payload.py" client "$transport" "$target_ip" 32001 "$test_timeout" - \
                >"$workdir/$payload_case-$transport-client.log" 2>&1 ||
                fail "$transport payload round trip failed"
            wait "$server_pid" || fail "$transport payload server failed"
        else
            expected="$workdir/$current_case-$transport-expected"
            received="$workdir/$current_case-$transport-received"
            printf 'easytier-mini-%s-%s-payload\n' "$current_case" "$transport" >"$expected"
            if [[ $transport == tcp ]]; then
                ip netns exec "$target_ns" timeout --kill-after=2 "$test_timeout" nc -l -p 32001 \
                    >"$received" 2>"$workdir/$current_case-$transport-server.log" </dev/null &
            else
                ip netns exec "$target_ns" timeout --kill-after=2 "$test_timeout" nc -u -l -p 32001 \
                    >"$received" 2>"$workdir/$current_case-$transport-server.log" </dev/null &
            fi
            server_pid=$!
            child_pids+=("$server_pid")
            wait_for "$transport netcat server" netcat_server_ready "$target_ns" "$transport" "$server_pid"
            status=0
            if [[ $transport == tcp ]]; then
                ip netns exec "$source" timeout --kill-after=2 "$test_timeout" nc -w 1 "$target_ip" 32001 \
                    <"$expected" >"$workdir/$current_case-$transport-client.log" 2>&1 || status=$?
            else
                ip netns exec "$source" timeout --kill-after=2 "$test_timeout" nc -u -w 1 "$target_ip" 32001 \
                    <"$expected" >"$workdir/$current_case-$transport-client.log" 2>&1 || status=$?
            fi
            (( status == 0 || status == 124 )) || fail "$transport netcat client failed: $status"
            wait_for "$transport netcat payload" cmp -s "$expected" "$received"
            kill -TERM "$server_pid" 2>/dev/null || true
            wait "$server_pid" 2>/dev/null || true
        fi
        printf 'PASS case=%s check=payload transport=%s backend=%s%s\n' \
            "$current_case" "$transport" "$payload_backend" "$family_field"
    done
}

run_static() {
    local transport=$1 ipv6_a= ipv6_b=
    current_case="static_$transport"
    if [[ $test_ipv6 == 1 ]]; then
        ipv6_a=fd42:6574:6d69:1::1
        ipv6_b=fd42:6574:6d69:1::2
    fi
    write_config "$workdir/a.toml" mini-a 10.251.1.1 "$transport" "" "$ipv6_a"
    write_config "$workdir/b.toml" peer-b 10.251.1.2 "$transport" "$transport://192.0.2.1:11010" "$ipv6_b"
    start_node "$ns_a" "$mini" "$workdir/a.toml" mini-a
    start_node "$ns_b" "$peer" "$workdir/b.toml" peer-b
    wait_for 'static TUN address A' has_tun_ipv4 "$ns_a" 10.251.1.1
    wait_for 'static TUN address B' has_tun_ipv4 "$ns_b" 10.251.1.2
    check_ping "$ns_a" 10.251.1.2
    check_ping "$ns_b" 10.251.1.1
    check_payload "$ns_a" "$ns_b" 10.251.1.2
    if [[ $test_ipv6 == 1 ]]; then
        wait_for 'static IPv6 TUN address A' has_tun_ipv6 "$ns_a" "$ipv6_a"
        wait_for 'static IPv6 TUN address B' has_tun_ipv6 "$ns_b" "$ipv6_b"
        check_ping_ipv6 "$ns_a" "$ipv6_b"
        check_ping_ipv6 "$ns_b" "$ipv6_a"
        check_payload "$ns_a" "$ns_b" "$ipv6_b"
    fi
    sample_metrics
    stop_nodes
}

dhcp_ready() {
    dhcp_a=$(tun_ipv4 "$ns_a") || return 1
    dhcp_b=$(tun_ipv4 "$ns_b") || return 1
    [[ $dhcp_a == 10.251.2.* && $dhcp_b == 10.251.2.* &&
       $dhcp_a != 10.251.2.1 && $dhcp_b != 10.251.2.1 && $dhcp_a != "$dhcp_b" ]]
}

dhcp_connected() {
    dhcp_ready && ping_once "$ns_a" "$dhcp_b" && ping_once "$ns_b" "$dhcp_a"
}

run_dhcp() {
    current_case=dhcp
    # A static seed makes this test work with upstream versions that wait for a subnet.
    write_config "$workdir/c.toml" mini-seed 10.251.2.1 tcp
    write_config "$workdir/b.toml" peer-dhcp dhcp tcp tcp://192.0.2.6:11010
    write_config "$workdir/a.toml" mini-dhcp dhcp tcp tcp://192.0.2.2:11010
    start_node "$ns_c" "$mini" "$workdir/c.toml" mini-seed
    start_node "$ns_b" "$peer" "$workdir/b.toml" peer-dhcp
    start_node "$ns_a" "$mini" "$workdir/a.toml" mini-dhcp
    wait_for 'static DHCP seed' has_tun_ipv4 "$ns_c" 10.251.2.1
    wait_for 'distinct reachable DHCP leases' dhcp_connected
    printf 'PASS case=dhcp check=distinct-addresses mini=%s peer=%s seed=10.251.2.1\n' "$dhcp_a" "$dhcp_b"
    check_ping "$ns_a" "$dhcp_b"
    check_ping "$ns_b" "$dhcp_a"
    sample_metrics
    stop_nodes
}

run_relay() {
    current_case=relay
    # No underlay route joins A and C; explicit peers and disabled P2P force B to relay.
    ip -n "$ns_a" route get 192.0.2.6 >/dev/null 2>&1 &&
        fail 'unexpected A-to-C underlay route'
    ip -n "$ns_c" route get 192.0.2.1 >/dev/null 2>&1 &&
        fail 'unexpected C-to-A underlay route'
    write_config "$workdir/b.toml" peer-relay 10.251.3.2 tcp
    write_config "$workdir/a.toml" mini-a 10.251.3.1 tcp tcp://192.0.2.2:11010
    write_config "$workdir/c.toml" mini-c 10.251.3.3 tcp tcp://192.0.2.5:11010
    start_node "$ns_b" "$peer" "$workdir/b.toml" peer-relay
    start_node "$ns_a" "$mini" "$workdir/a.toml" mini-a
    start_node "$ns_c" "$mini" "$workdir/c.toml" mini-c
    wait_for 'relay TUN address A' has_tun_ipv4 "$ns_a" 10.251.3.1
    wait_for 'relay TUN address C' has_tun_ipv4 "$ns_c" 10.251.3.3
    check_ping "$ns_a" 10.251.3.3
    check_ping "$ns_c" 10.251.3.1
    check_payload "$ns_a" "$ns_c" 10.251.3.3
    sample_metrics
    stop_nodes
}

printf 'RUN mini=%s peer=%s timeout_seconds=%s\n' "$mini" "$peer" "$test_timeout"
create_namespace "$ns_a"
create_namespace "$ns_b"
create_namespace "$ns_c"
create_link "$ns_a" ab0 192.0.2.1 "$ns_b" ba0 192.0.2.2
create_link "$ns_b" bc0 192.0.2.5 "$ns_c" cb0 192.0.2.6
run_static tcp
run_static udp
if [[ $skip_dhcp == 1 ]]; then
    printf 'SKIP case=dhcp check=all reason=ET_MINI_TEST_SKIP_DHCP\n'
else
    run_dhcp
fi
run_relay
printf 'PASS case=all check=complete\n'
