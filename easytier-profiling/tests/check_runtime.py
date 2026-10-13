#!/usr/bin/env python3
"""Assert real smoke artifacts; a profiler process exiting zero is not sufficient."""

import argparse
from collections import Counter
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "backend",
    choices=["off", "tracing", "hotpath", "hotpath-alloc", "hotpath-cpu", "lttng"],
)
parser.add_argument(
    "artifact", type=Path, help="stderr, hotpath JSON, or babeltrace2 text output"
)
parser.add_argument("--rounds", type=int, default=32)
args = parser.parse_args()
text = args.artifact.read_text()

if args.backend == "off":
    assert not text.strip(), "disabled profiling emitted diagnostics"
elif args.backend == "tracing":
    lines = text.splitlines()
    counts = Counter(line.rsplit(": ", 1)[-1] for line in lines)
    assert counts["new"] == counts["close"] == args.rounds + 2, counts
    assert counts["enter"] == counts["exit"], counts
    assert (
        sum("smoke::compute:" in line and line.endswith(": new") for line in lines)
        == args.rounds
    )
    assert any(
        "smoke::work:smoke::compute:" in line for line in lines
    ), "missing parent context"
    assert any(
        "smoke::cancelled:" in line and line.endswith(": close") for line in lines
    ), "cancelled span leaked"
    assert any(
        f"rounds={args.rounds}" in line and "checksum=" in line for line in lines
    ), "missing event fields"
elif args.backend.startswith("hotpath"):
    report = json.loads(text)
    functions = {row["name"]: row for row in report["functions_timing"]["data"]}
    assert functions["smoke::compute"]["calls"] == args.rounds
    assert functions["smoke::work"]["calls"] == 1
    assert functions["smoke::cancelled"]["calls"] == 1
    (channel,) = report["channels"]["data"]
    assert channel["sent_count"] == channel["received_count"] == args.rounds
    assert channel["queue_size"] == 0 and channel["state"] == "closed"
    future = next(
        row for row in report["futures"]["data"] if row["label"] == "smoke::work"
    )
    assert future["call_count"] == 1 and future["total_polls"] >= args.rounds + 1
    (mutex,) = report["mutexes"]["data"]
    assert mutex["count"] == args.rounds + 1
    values = {
        row["expression"]: row["last_value"] for row in report["debug"]["entries"]
    }
    assert int(values["smoke.rounds"]) == args.rounds
    if args.backend == "hotpath-alloc":
        allocations = {row["name"]: row for row in report["functions_alloc"]["data"]}
        assert allocations["smoke::compute"]["calls"] == args.rounds
        assert allocations["smoke::compute"]["avg"] == "4.0 KB", allocations
    if args.backend == "hotpath-cpu":
        cpu = report["functions_cpu"]
        assert (
            "message" not in cpu
        ), f"CPU collection failed despite successful process exit: {cpu}"
        assert cpu["attributed_samples"] > 0, cpu
        assert any(
            row["name"] == "smoke::compute" and row["samples"] > 0
            for row in cpu["data"]
        ), cpu
elif args.backend == "lttng":
    spans = {}
    active = Counter()
    counts = Counter()
    compute_count = 0
    cancelled_closed = False
    for line in text.splitlines():
        match = re.search(r"easytier:(\w+):", line)
        assert match, f"unexpected trace line: {line}"
        kind = match[1]
        counts[kind] += 1
        if kind == "event":
            assert f"rounds={args.rounds}" in line and "checksum=" in line, line
            continue
        ident = int(re.search(r"\bid = (\d+)", line)[1])
        if kind == "span_new":
            assert ident not in spans, "span ID reused before close"
            name = re.search(r'\bname = "([^"]+)"', line)[1]
            parent = int(re.search(r"\bparent = (\d+)", line)[1])
            if name == "smoke::compute":
                assert spans[parent] == "smoke::work", "missing parent relation"
                compute_count += 1
            spans[ident] = name
        elif kind == "span_enter":
            assert ident in spans
            active[ident] += 1
        elif kind == "span_exit":
            active[ident] -= 1
            assert active[ident] >= 0
        elif kind == "span_close":
            assert active[ident] == 0
            cancelled_closed |= spans.pop(ident) == "smoke::cancelled"
    assert not spans and not any(active.values()), "span lifecycle is unbalanced"
    assert compute_count == args.rounds and cancelled_closed
    assert counts["span_new"] == counts["span_close"] == args.rounds + 2
    assert counts["event"] == 1
print(f"{args.backend}: runtime artifact checks passed")
