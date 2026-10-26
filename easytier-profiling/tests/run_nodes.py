#!/usr/bin/env python3
"""Exercise two real EasyTier nodes and verify a 1 MiB tunneled TCP echo.

No TUN, root privileges, public peers, STUN servers, or host routes are needed.
Build the desired backend first; run this script once per backend.
"""

import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--core", type=Path, default=root / "target/debug/easytier-core")
parser.add_argument("--cli", type=Path, default=root / "target/debug/easytier-cli")
parser.add_argument("--secure", action="store_true")
parser.add_argument(
    "--hotpath", action="store_true", help="also check both live hotpath HTTP endpoints"
)
options = parser.parse_args()
out = options.output.resolve()
out.mkdir(parents=True, exist_ok=False)
core, cli = str(options.core.resolve()), str(options.cli.resolve())
used_ports = set()


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        candidate = s.getsockname()[1]
    if candidate in used_ports:
        return port()
    used_ports.add(candidate)
    return candidate


listen, rpc_a, rpc_b = port(), port(), port()
forward = port()
metrics = [port(), port()]
echo = socket.socket()
echo.bind(("127.0.0.1", 0))
echo.listen()
echo_port = echo.getsockname()[1]
echo.settimeout(1)
echo_stop = threading.Event()


def echo_server():
    while not echo_stop.is_set():
        try:
            conn, _ = echo.accept()
        except TimeoutError:
            continue
        with conn:
            conn.settimeout(10)
            while block := conn.recv(65536):
                conn.sendall(block)


thread = threading.Thread(target=echo_server, daemon=True)
thread.start()
processes = []
logs = []
try:
    for index, rpc in enumerate([rpc_a, rpc_b]):
        args = [
            core,
            "--network-name",
            "profiling-validation",
            "--network-secret",
            "local-test-only",
            "--hostname",
            "profile-" + str(index),
            "--instance-name",
            "profile-" + str(index),
            "--rpc-portal",
            f"127.0.0.1:{rpc}",
            "--console-log-level",
            "warn",
            "--disable-p2p",
            "true",
            "--disable-ipv6",
            "true",
            "--bind-device",
            "false",
            "--stun-servers",
            "--no-tun",
            "true",
            "--ipv4",
            f"10.254.77.{index+1}",
        ]
        if options.secure:
            args += ["--secure-mode", "true"]
        if index == 0:
            args += [
                "--listeners",
                f"tcp://127.0.0.1:{listen}",
                "--proxy-networks",
                "127.0.0.1/32",
            ]
        else:
            args += [
                "--no-listener",
                "--peers",
                f"tcp://127.0.0.1:{listen}",
                "--port-forward",
                f"tcp://127.0.0.1:{forward}/127.0.0.1:{echo_port}",
            ]
        env = os.environ.copy()
        env.update(
            HOTPATH_METRICS_PORT=str(metrics[index]),
            HOTPATH_REPORT="all",
            HOTPATH_LIMIT="0",
            HOTPATH_OUTPUT_FORMAT="json",
            HOTPATH_OUTPUT_PATH=str(out / f"node-{index}.json"),
        )
        log = open(out / f"node-{index}.log", "w")
        logs.append(log)
        processes.append(
            subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=env)
        )
    deadline = time.monotonic() + 25
    last = None
    while time.monotonic() < deadline:
        for p in processes:
            if p.poll() is not None:
                raise RuntimeError(f"node exited early: {p.returncode}")
        result = subprocess.run(
            [cli, "-p", f"127.0.0.1:{rpc_b}", "-o", "json", "peer"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        last = result.stdout + result.stderr
        if result.returncode == 0 and "profile-0" in result.stdout:
            (out / "peer-b.json").write_text(result.stdout)
            break
        time.sleep(0.25)
    else:
        raise RuntimeError("peers did not connect: " + str(last))
    time.sleep(1)
    payload = bytes(range(256)) * 4096
    received = bytearray()
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", forward), timeout=10) as stream:
        # Bound each echo round to avoid relying on socket buffer capacity.
        for offset in range(0, len(payload), 16384):
            block = payload[offset : offset + 16384]
            stream.sendall(block)
            chunk = bytearray()
            while len(chunk) < len(block):
                data = stream.recv(len(block) - len(chunk))
                if not data:
                    raise RuntimeError("unexpected EOF during tunneled payload")
                chunk.extend(data)
            received.extend(chunk)
    assert bytes(received) == payload
    (out / "payload.json").write_text(
        json.dumps(
            {
                "bytes": len(payload),
                "sha256": hashlib.sha256(received).hexdigest(),
                "elapsed_s": time.monotonic() - started,
            },
            indent=2,
        )
    )
    time.sleep(1)
    for index, rpc in enumerate([rpc_a, rpc_b]):
        for command in ["peer", "stats"]:
            result = subprocess.run(
                [cli, "-p", f"127.0.0.1:{rpc}", "-o", "json", command],
                capture_output=True,
                text=True,
                timeout=8,
            )
            (out / f"{command}-{index}.json").write_text(result.stdout)
            if result.returncode:
                raise RuntimeError(result.stderr)
    if options.hotpath:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for index, metric_port in enumerate(metrics):
            for endpoint in ["functions_timing", "channels", "futures", "mutexes"]:
                with opener.open(
                    f"http://127.0.0.1:{metric_port}/{endpoint}", timeout=5
                ) as response:
                    report = json.load(response)
                (out / f"live-{index}-{endpoint}.json").write_text(
                    json.dumps(report, indent=2)
                )
                assert report["data"], (index, endpoint, report)
    for index in range(2):
        peers = json.loads((out / f"peer-{index}.json").read_text())
        remote = next(
            peer for peer in peers if peer["hostname"] == f"profile-{1-index}"
        )
        assert remote["tunnel_proto"] == "tcp", remote
        counters = {
            entry["name"]: int(entry.get("value") or 0)
            for entry in json.loads((out / f"stats-{index}.json").read_text())
        }
        assert counters["traffic_bytes_tx"] >= len(payload), counters
        assert counters["traffic_bytes_rx"] >= len(payload), counters
    print(
        "Two TCP peers echoed 1 MiB with matching SHA-256 and nonzero tunnel counters: "
        + str(out)
    )
finally:
    for p in processes:
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
    statuses = []
    for p in processes:
        try:
            statuses.append(p.wait(timeout=30))
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            statuses.append("timeout")
    echo_stop.set()
    thread.join(timeout=2)
    echo.close()
    for log in logs:
        log.close()
    (out / "exit-status.json").write_text(json.dumps(statuses))
    if any(status != 0 for status in statuses):
        raise RuntimeError("unclean shutdown: " + repr(statuses))
