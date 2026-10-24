# Runtime validation of the profiling backends

Implementation under test: `742c6fa6` (the implementation is unchanged by these
additional runtime tests). Environment: Fedora 44 x86_64, Rust 1.95,
hotpath 0.21.5, LTTng tools/UST 2.14, samply 0.13.1.

These are functional runtime checks, not throughput benchmarks. Tests used debug
binaries with symbols. Each backend was built and run separately.

## Results

| Configuration | Actual runtime evidence | Result |
| --- | --- | --- |
| Disabled | Identical workload checksum, no profiling output; two native nodes echo 1 MiB | Pass |
| `profiling` / facade `tracing` | Formatted tracing output: 34 spans created/closed, balanced enter/exit, parent context, cancellation and event fields; two native nodes echo 1 MiB | Pass |
| `hotpath` | JSON report: 32 channel sends/receives, 33 work-Future polls, 33 mutex acquisitions; live HTTP endpoints on both native nodes; 1 MiB echo | Pass |
| `hotpath-alloc` | Each of 32 compute calls allocates 4 KiB, 128 KiB total; native nodes produce allocation reports and echo 1 MiB, including secure mode | Pass |
| `hotpath-cpu`, default sampler | Process exits successfully **but report contains a CPU collection error**: samply requires `perf_event_paranoid <= 1`, host has `2` | Environment-blocked, not a pass |
| `hotpath-cpu`, userspace perf test adapter | Real `cpu-clock:u` samples imported by samply and attributed by hotpath; compute accounts for 96.97% of weighted CPU samples in the checked run; two native nodes also produce nonzero attribution and echo 1 MiB | Conditional pass; explicit alternative collector |
| `lttng` | Actual CTF decoded by Babeltrace2: 207 smoke events, 34 spans created/closed, parentage and cancellation checked; also passes when recording starts after callsite warmup; native-node capture has 97,964 events during a 1 MiB echo | Pass |

A further secure-mode LTTng run produced 130,676 events from two processes,
including 2,083 calls each to `SecureDatagramSession::encrypt_payload` and
`SecureDatagramSession::decrypt_payload`.

All 1 MiB payloads have SHA-256:

```text
fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83
```

The node test uses two processes, a loopback TCP tunnel, a subnet-proxy route and
local TCP port forwarding to an echo server. Both tunnel byte counters must
exceed the payload size; this prevents a local-only echo from falsely passing.
No TUN device, privileged routes, public peers, or STUN servers are used. Nodes
exit cleanly on SIGTERM. `--bind-device false` is necessary for this loopback
setup; the default device binding initially caused connection timeouts even in
the disabled baseline.

The full LTTng node trace has balanced enter/exit events and no span-ID reuse
before close. Two pending `MpscTunnel::forward_one_round` spans survive until
process exit without a close event. Consumers must treat process termination as
an interrupted lifetime, not invent a completed duration. The bounded smoke
workload, including an explicitly cancelled Future, has no unclosed spans.

## Reproduce artifact checks

From the repository root, choose a fresh artifact directory:

```sh
out="${TMPDIR:-$HOME/tmp}/pi/profiling-runtime-$(date +%s)"
mkdir -p "$out"
for backend in off tracing hotpath hotpath-alloc; do
  features="$backend"
  if [ "$backend" = off ]; then features=""; fi
  HOTPATH_REPORT=all HOTPATH_OUTPUT_FORMAT=json HOTPATH_OUTPUT_PATH="$out/$backend.json" \
    cargo run --locked -q -p easytier-profiling --example smoke --features "$features" \
    > "$out/$backend.stdout" 2> "$out/$backend.stderr"
  grep -qx 'rounds=32 checksum=3622563998815325168' "$out/$backend.stdout"
  artifact="$out/$backend.json"
  if [ "$backend" = off ] || [ "$backend" = tracing ]; then artifact="$out/$backend.stderr"; fi
  python3 easytier-profiling/tests/check_runtime.py "$backend" "$artifact"
done
```

`check_runtime.py` checks counts, parentage, cancellation, fields and allocation
size, not merely the presence of a file or a successful exit status. Its CPU
check rejects the failed default-sampler report even though the program exits 0.

### LTTng capture

Install LTTng-UST development headers, libclang, LTTng tools, and Babeltrace2
using the normal platform package workflow. In this validation, signed Fedora
RPMs were extracted into a temporary directory rather than installed globally.
No kernel tracer was enabled.

Use the capture commands in [README.md](README.md#lttng), then:

```sh
babeltrace2 "$PWD/easytier-trace" > "$out/lttng.txt"
python3 easytier-profiling/tests/check_runtime.py lttng "$out/lttng.txt"
```

For late activation, start the smoke executable with `SMOKE_WARMUP=1` and
`SMOKE_START_DELAY_MS=2500`, wait for `warmup complete` on stderr, and only then
create/start the session. The second workload uses already-registered callsites.
Decode that capture and run the same checker.

### CPU collection without changing host policy

The default hotpath sampler needs its normal `hotpath-samply`/samply setup and
permissions. Do not count a report containing `functions_cpu.message` as success.

Where user-space-only perf events are permitted, the **test-only** adapter can
exercise CPU attribution without relaxing global sysctls:

```sh
HOTPATH_SAMPLY_WRAPPER_BIN="$PWD/easytier-profiling/tests/userspace_perf.py" \
HOTPATH_TEST_ARTIFACT_DIR="$out/cpu-samples" \
HOTPATH_REPORT=all HOTPATH_OUTPUT_FORMAT=json HOTPATH_OUTPUT_PATH="$out/cpu.json" \
SMOKE_ROUNDS=2048 SMOKE_START_DELAY_MS=1000 \
  cargo run --locked -q -p easytier-profiling --example smoke --features hotpath-cpu
python3 easytier-profiling/tests/check_runtime.py hotpath-cpu "$out/cpu.json" --rounds 2048
```

This requires `perf` and `samply` on PATH. The adapter records `cpu-clock:u`, uses
small mmap buffers, and imports the actual perf.data into Firefox profile JSON.
It never modifies permissions or sysctls. It is not the production default and
can still fail on more restrictive hosts. The small buffers avoid exceeding
mlock limits when profiling two multi-threaded native processes simultaneously.
Hotpath's `samples` fields are weighted attribution values, not the raw perf
record count.

## Reproduce the native-node tests

Build and test sequentially: Cargo overwrites the common executable paths when
features change. Do not build a different backend while a test is selecting its
binaries.

```sh
cargo build --locked -p easytier --bins --features aes-gcm,hotpath
python3 easytier-profiling/tests/run_nodes.py --hotpath --output "$out/nodes-hotpath"

cargo build --locked -p easytier --bins --features aes-gcm,hotpath-alloc
python3 easytier-profiling/tests/run_nodes.py --hotpath --secure --output "$out/nodes-alloc-secure"
```

Repeat with `aes-gcm` alone, `aes-gcm,profiling`, or `aes-gcm,lttng`, omitting
`--hotpath`. For LTTng, start the recording before running the node script and
stop it after both nodes exit. For CPU, build `aes-gcm,hotpath-cpu` and set the
collector environment as above. The script gives each hotpath process a separate
metrics port, checks live timing/channel/Future/mutex endpoints, and saves peer
snapshots, counters, per-node reports, payload checksum and exit statuses.

Local artifacts for this validation are retained under:
`/home/fanmi/tmp/pi/profiling-validation/artifacts`.
