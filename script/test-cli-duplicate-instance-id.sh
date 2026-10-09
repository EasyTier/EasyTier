#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
export CORE_BIN=${CORE_BIN:-"$REPO_ROOT/target/debug/easytier-core"}
export CLI_BIN=${CLI_BIN:-"$REPO_ROOT/target/debug/easytier-cli"}
if [[ ${SKIP_BUILD:-0} != 1 || ! -x "$CORE_BIN" || ! -x "$CLI_BIN" ]]; then
  (cd "$REPO_ROOT" && cargo build -p easytier --bin easytier-core --bin easytier-cli)
fi

"${PYTHON_BIN:-python3}" - <<'PY'
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid

core = str(Path(os.environ["CORE_BIN"]).resolve())
cli = str(Path(os.environ["CLI_BIN"]).resolve())
processes, logs, ports = [], [], set()
base = Path(os.environ.get("TMPDIR") or Path.home() / "tmp") / "pi"
base.mkdir(parents=True, exist_ok=True)


def free_port():
    while True:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            value = sock.getsockname()[1]
        if value not in ports:
            ports.add(value)
            return value


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def wait_for(predicate):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass
        time.sleep(0.1)
    raise AssertionError("Timed out waiting for the expected route snapshot")


with tempfile.TemporaryDirectory(prefix="easytier-duplicate-id-", dir=base) as temp:
    root = Path(temp)
    env = {k: v for k, v in os.environ.items() if not k.startswith("ET_")}
    env.update(HOME=str(root / "home"), XDG_CONFIG_HOME=str(root / "config"), XDG_DATA_HOME=str(root / "data"))
    (root / "home").mkdir()
    admin_configs = root / "admins"
    admin_configs.mkdir()
    rpc_port = free_port()
    listener_a, listener_b = free_port(), free_port()
    duplicate_id = str(uuid.uuid4())

    def config(path, name, instance_id, network, ip, listeners, peer=None):
        peer_config = f'\n[[peer]]\nuri = "{peer}"\n' if peer else ""
        path.write_text(f'''instance_name = "{name}"
instance_id = "{instance_id}"
hostname = "{name}"
ipv4 = "{ip}/24"
listeners = {json.dumps(listeners)}
stun_servers = []
tcp_stun_servers = []
stun_servers_v6 = []
[network_identity]
network_name = "duplicate-id-e2e-{network}"
network_secret = "test-only"
{peer_config}
[flags]
no_tun = true
enable_ipv6 = false
disable_p2p = true
bind_device = false
''')

    def launch(label, args):
        log = open(root / f"{label}.log", "w")
        logs.append(log)
        process = subprocess.Popen([core] + args, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        return process

    def query(command, flags=(), name=None, portal=rpc_port):
        args = [cli, "-p", f"127.0.0.1:{portal}"]
        if name:
            args += ["--instance-name", name]
        return subprocess.run(args + list(flags) + [command], cwd=root, env=env, text=True, capture_output=True, check=True, timeout=10)

    def snapshot(name):
        return json.loads(query("route", ["-v"], name=name).stdout)

    def duplicate_peers():
        data = snapshot("e2e-inst-a")
        peers = [pair["route"]["peer_id"] for pair in data["peer_routes"] if pair["route"].get("inst_id") == duplicate_id]
        return sorted(peers) if len(set(peers)) == 2 else None

    try:
        for network, listener in [("a", listener_a), ("b", listener_b)]:
            config(admin_configs / f"{network}.toml", f"e2e-inst-{network}", str(uuid.uuid4()), network, f"10.253.{1 if network == 'a' else 2}.1", [f"tcp://127.0.0.1:{listener}"])
        launch("admins", ["--config-dir", str(admin_configs), "--rpc-portal", f"127.0.0.1:{rpc_port}"])
        wait_for(lambda: len(json.loads(query("node", ["-o", "json"]).stdout)) == 2)
        clients = []
        for label, network, listener, ip in [("client-a", "a", listener_a, "10.253.1.2"), ("client-b", "a", listener_a, "10.253.1.3"), ("client-c", "b", listener_b, "10.253.2.2")]:
            path = root / f"{label}.toml"
            config(path, label, duplicate_id, network, ip, [], f"tcp://127.0.0.1:{listener}")
            portal = free_port()
            clients.append((launch(label, ["-c", str(path), "--rpc-portal", f"127.0.0.1:{portal}"]), path, portal))
        peers = wait_for(duplicate_peers)
        wait_for(lambda: len(snapshot("e2e-inst-b")["peer_routes"]) == 1)
        expected_ids = "peer IDs [" + ", ".join(map(str, peers)) + "]"

        expected_columns = {
            "peer": set("cidr ipv4 hostname cost lat_ms loss_rate rx_bytes tx_bytes tunnel_proto nat_type id version".split()),
            "route": set("ipv4 hostname proxy_cidrs next_hop_ipv4 next_hop_hostname next_hop_lat path_len path_latency next_hop_ipv4_lat_first next_hop_hostname_lat_first path_len_lat_first path_latency_lat_first version".split()),
        }
        for command in ["peer", "route"]:
            for flags in [[], ["-o", "json"], ["-v"], ["-v", "-o", "json"]]:
                result = query(command, flags)
                assert result.stderr.count("duplicate instance_id detected") == 1, f"{command} {flags}: expected one duplicate-ID warning, got {result.stderr!r}"
                assert "Warning [e2e-inst-a (" in result.stderr, result.stderr
                assert duplicate_id in result.stderr and expected_ids in result.stderr, result.stderr
                assert "duplicate instance_id detected" not in result.stdout, result.stdout
                if flags:
                    data = json.loads(result.stdout)
                    assert {item["instance_name"] for item in data} == {"e2e-inst-a", "e2e-inst-b"}
                    assert all(set(item) == {"instance_name", "instance_id", "result"} for item in data)
                    if flags == ["-o", "json"]:
                        assert all(set(row) == expected_columns[command] for item in data for row in item["result"])
                unaffected = query(command, flags, name="e2e-inst-b")
                assert unaffected.stderr == "", unaffected.stderr
        selected_id = snapshot("e2e-inst-a")["node_info"]["inst_id"]
        for command in ["peer", "route"]:
            for selector in [["--instance-name", "e2e-inst-a"], ["--instance-id", selected_id]]:
                result = query(command, selector + ["-o", "json"])
                assert "Warning [local peer " in result.stderr and expected_ids in result.stderr, result.stderr
                assert isinstance(json.loads(result.stdout), list)
        print("PASS remote duplicates, output modes, selectors, stderr-only warnings, and instance isolation")

        client, path, portal = clients[0]
        wait_for(lambda: len(json.loads(query("route", ["-v"], portal=portal).stdout)["peer_routes"]) == 2)
        for command in ["peer", "route"]:
            result = query(command, ["-o", "json"], portal=portal)
            assert result.stderr.count("duplicate instance_id detected") == 1 and expected_ids in result.stderr, result.stderr
            json.loads(result.stdout)
        print("PASS local UUID colliding with a remote peer")

        stop(clients[1][0])
        wait_for(lambda: len(snapshot("e2e-inst-a")["peer_routes"]) == 1)
        for command in ["peer", "route"]:
            assert query(command, ["-o", "json"]).stderr == ""
        new_id = str(uuid.uuid4())
        path = clients[1][1]
        path.write_text(path.read_text().replace(duplicate_id, new_id))
        launch("client-b-restarted", ["-c", str(path), "--rpc-portal", f"127.0.0.1:{free_port()}"])
        wait_for(lambda: len(snapshot("e2e-inst-a")["peer_routes"]) == 2)
        for command in ["peer", "route"]:
            assert query(command, ["-o", "json"]).stderr == ""
        print("PASS warnings clear after disconnect and after assigning a unique UUID")
    finally:
        for process in reversed(processes):
            stop(process)
        for log in logs:
            log.close()
PY
