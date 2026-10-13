# EasyTier profiling

Business code uses `easytier_profiling` regardless of the selected backend.
The facade delegates measurement and specialized wrappers to hotpath; it does
not translate tracing spans into a partial hotpath implementation.

## Build selection

Features on the `easytier` and `easytier-core` packages:

| Feature | Implementation |
| --- | --- |
| None (default) | No profiling; original function bodies and wrapper inputs |
| `profiling` | `tracing` spans/events, without a bundled profiling exporter |
| `lttng` | `profiling` plus the LTTng-UST tracing layer (Linux only) |
| `hotpath` | Native hotpath timing, Future, channel and lock instrumentation |
| `hotpath-cpu` | hotpath plus CPU sampling; disables instrumented function inlining |
| `hotpath-alloc` | hotpath plus allocation tracking |

`hotpath*` and `profiling`/`lttng` are mutually exclusive. Cargo features are
additive across a build: do not use `--all-features`. The existing `easytier`
`tracing` feature still means tokio-console and can coexist with either backend.
On this facade crate itself, the tracing feature is called `tracing`.

```sh
cargo build -p easytier --release --features hotpath
cargo build -p easytier --release --features hotpath-alloc
# Linux, with liblttng-ust-dev and libclang-dev installed:
cargo build -p easytier --release --features lttng
```

The `easytier-core` executable owns a hotpath guard until shutdown. In allocation
mode its global counting allocator uses System; combining `hotpath-alloc` with
`mimalloc` or `jemalloc` is rejected at compile time. Timing-only hotpath works
with either allocator. Embedded users must create their own
`HotpathGuardBuilder` guard, and in allocation mode install a `CountingAllocator`
at their executable boundary. Library crates never install a global allocator or
subscriber.

hotpath 0.21 is used to match the restoration PR's API family. Runtime hotpath
settings still work, e.g. `HOTPATH_REPORT=all` to include specialized reports.
This configures the compiled backend; it does not switch backends at runtime.
CPU reports additionally need hotpath's native samply setup, profiling permissions,
and a binary with debug symbols; a successful feature build alone does not verify
CPU sample attribution.

## Instrumentation

```rust,ignore
use easytier_profiling as profiling;

#[profiling::instrument("Peer::send")]
async fn send(packet: Packet) -> Result<(), Error> {
    // No automatic argument or result capture: packets may contain secrets.
    profiling::event!("send", bytes = packet.len());
    transmit(packet).await
}

let result = profiling::scope!("decode", decode(bytes));
let result = profiling::scope_async!("request", request()).await;
let (tx, rx) = profiling::channel!(tokio::sync::mpsc::channel(128));
let lock = profiling::mutex!(tokio::sync::Mutex::new(state));
```

`instrument` accepts an optional literal name; without one it uses module path
and function name. Supply a type-qualified name for methods to avoid aggregation
collisions. This attribute handles ordinary sync and async functions. For methods
rewritten by `async_trait` or synchronous functions returning a Future, put
`scope_async!` around the Future body explicitly; instrumenting their synchronous
wrapper alone would measure construction, not execution.

`scope!` is **synchronous only**; never hold its entered span/measurement guard
across `.await`. Use `scope_async!` for a Future instead. Async function
instrumentation uses hotpath's `measure_async_future` API, or tracing's
`Instrument` wrapper. Tracing enters/exits on each poll, including when a task
moves between threads; the span lifetime also includes suspended time. Poll
active time is not OS thread CPU time. Cancellation drops the span normally.

`channel!`, `mutex!`, `rw_lock!`, `future!`, and `stream!` are native hotpath
macros when enabled, otherwise identity expressions. Use `profiling::wrap` types
where wrapped endpoints or locks occur in type positions. Without hotpath,
wrapper inputs are evaluated exactly once and hotpath-specific options are not
evaluated. This does not emulate channel/lock statistics with tracing events.

`event!("name", field = expression, ...)` records Debug values: hotpath stores
one value per `name.field`, while tracing stores one event with named fields.
With profiling disabled neither values nor labels are evaluated. Do not record
packet contents, keys, or other secrets.

The initial migrated sites cover peer receive channels, connection send paths,
peer-map/relay forwarding, route lookup, packet processing, compression/encryption,
session crypto, peer synchronization locks, and MPSC tunnel forwarding. Remaining transport-specific sites can use the
same API without backend conditionals.

## LTTng

The native logger composes `LttngLayer` with its existing subscriber, selecting
only `easytier::profiling` targets for LTTng and excluding them from text logs.
Log verbosity does not gate profiling. The reusable layer itself has no global
filter and can also consume arbitrary tracing instrumentation in an embedding
application.

The `easytier` provider emits:

- `span_new`: id, parent id (0 for a root), name, target, initial fields;
- `span_enter` / `span_exit`: poll or synchronous execution boundaries;
- `span_close`: lifetime end;
- `span_record` / `span_follows_from`: field updates and causal links;
- `event`: parent id, name, target, level, fields.

Fields are formatted as named Debug values, not a typed CTF schema per business
event. Span IDs are process-local and may be reused after close. Include process
and thread context for analysis. The layer deliberately does not cache UST
session state as `Interest::never`, so starting a session after program startup
works. A compiled LTTng build still pays tracing registry/callback costs without
an active recording session; this is not a zero-overhead disabled mode. Default
(non-profiling) builds do not link LTTng or hotpath.

Example capture (requires the LTTng CLI/session daemon as well as UST):

```sh
lttng create easytier-profile --output="$PWD/easytier-trace"
lttng enable-event --userspace 'easytier:*'
lttng add-context --userspace --type=vpid --type=vtid
lttng start
cargo run -p easytier-profiling --example smoke --features lttng
lttng stop
lttng destroy easytier-profile
babeltrace2 "$PWD/easytier-trace"
```

For a hotpath smoke report:

```sh
HOTPATH_REPORT=all cargo run -p easytier-profiling --example smoke --features hotpath
HOTPATH_REPORT=all cargo run -p easytier-profiling --example smoke --features hotpath-alloc
```

## Validation

```sh
for features in '' tracing hotpath hotpath-cpu hotpath-alloc lttng; do
  cargo test -p easytier-profiling --no-default-features --features "$features"
done
```

Tests cover sync/async control flow, Send futures, single evaluation, channel and
lock operations, disabled arguments, span parentage, per-poll enter/exit,
cancellation, and LTTng layer composition. Feature builds are not a throughput
benchmark: enabled-backend overhead and real packet forwarding performance need
separate measurement.

### Runtime evidence

See [VALIDATION.md](VALIDATION.md) for backend-specific results and repeatable
artifact checks, including two real nodes echoing 1 MiB through a TCP tunnel.
The CPU check rejects sampler errors even when the profiled program exits 0.
