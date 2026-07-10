# Go Host and WASI Core Phase 0 PoC

> Status: active Phase 0 design. Updated 2026-07-10.

## Question to answer

Can a pure-Go host, initially wazero, drive a `wasm32-wasip1` build of the
single `easytier-core` crate while core retains current-thread Tokio and while
DNS, TCP, and UDP are asynchronous host capabilities?

The PoC must answer this before the rest of the refactor depends on a particular
wasm ABI or scheduling strategy.

## What is already proven

At baseline commit `40fb39b5`:

- `easytier-core` builds for `wasm32-wasip1` with default, no-default, and
  all-features configurations;
- pure-Go wazero 1.12.0 executes 220 default/no-default tests and 239
  all-features tests successfully;
- the observed WASI imports include clock, random, and polling facilities;
- the core Tokio feature set is `sync`, `macros`, `io-util`, `rt`, and `time`,
  which is within Tokio's documented stable wasm support.

This proves compilation and finite test execution. It does not prove that a Go
host can sustain an indefinitely running networking instance.

## Constraints

1. Tokio stays internal to core. Tokio runtime handles, tasks, and futures do
   not cross the host seam.
2. One wasm module instance uses current-thread Tokio. Multi-thread Tokio is not
   part of this design.
3. A wazero exported function call runs synchronously on the calling Go
   goroutine. Calls into the same module instance are serialized and are never
   re-entrant.
4. A host import must not wait for an individual socket, DNS result, or timer in
   a way that blocks the only guest executor.
5. Potentially blocking Go work runs in Go goroutines. The host later delivers
   a Completion during a drive.
6. Go does not retain a borrowed slice into wasm memory after a call returns.
   Data is copied or represented by opaque handles. Memory growth must not
   invalidate host state.
7. Normal cancellation is cooperative. Closing the whole module is reserved for
   a stuck-instance hard kill.
8. The first PoC uses pure Go and no cgo so the embedding and deployment model
   remains representative.

## Candidate runtime models

### Model A: long-running guest with blocking per-operation imports

Core calls `tcp_read`, `udp_recv`, or `dns_resolve`; the import blocks until the
specific result is ready.

Reject this model. One pending operation can freeze unrelated connections,
Tokio timers, cancellation, and peer maintenance on the current-thread runtime.

### Model B: bounded cooperative drives

Go is the drive owner. Each serialized drive supplies commands and available
Completions, lets core make bounded progress, and receives new Operations plus
the next wake requirement before returning. Go waits for operation completion,
external commands, or the next timer deadline and invokes the next drive.

This is the primary model to prototype because it keeps Go in control and
makes the no-overlap rule explicit. The experiment must determine how Tokio's
current-thread scheduler is advanced without busy polling and how timer
deadlines are surfaced accurately.

### Model C: centralized multiplex wait

Core enters one host import that waits for any completion or the next deadline,
not for an individual socket. This can avoid idle polling while preserving one
executor wake point.

Prototype this only if Model B cannot provide efficient idle waiting. The wait
must be centralized, cancellable, and able to wake for any connection; it must
not turn into blocking imports spread across socket Implementations.

The Phase 0 result selects Model B, Model C, or a documented combination. It
must not leave both as accidental production modes.

## PoC shape

Use a disposable Go harness and the real `easytier-core` wasm artifact. Keep the
cross-wasm surface narrow and group it into three Interface categories:

- lifecycle: create, configure, start, request stop, inspect terminal state,
  and destroy a Core instance;
- drive exchange: submit commands and Completions, make bounded progress, and
  return Operations, events, and a wake requirement;
- owned data transfer: allocate/write/read/release serialized batches without
  retaining borrowed guest memory.

Exact function names, binary encoding, and memory ownership details are outputs
of the PoC, not assumptions in this document. The production Interface should
be recorded in a follow-up ADR after measurement.

Inside Go:

```text
serialized drive owner
        |
        +-- command/completion queue
        +-- timer wake
        +-- DNS workers
        +-- TCP workers
        +-- UDP workers
        +-- packet I/O workers
```

Workers may complete concurrently, but only the drive owner calls the wasm
instance. Host Implementations translate opaque operation handles to Go
resources and never call back into wasm from an import.

## Milestones

### P0.1: artifact and lifecycle seam

- build one reproducible `easytier-core` `wasm32-wasip1` artifact;
- instantiate two modules in one Go process;
- apply distinct minimal configurations;
- start, drive, cooperatively stop, and destroy both instances repeatedly;
- record the import allowlist and prove no unintended networking imports.

This milestone may initially use an in-memory clocked operation to prove the
drive mechanics before adding sockets.

### P0.2: DNS and TCP

- implement Go DNS and TCP Host Adapters using operation handles;
- keep one TCP read pending indefinitely while another connection exchanges
  data and Tokio timers continue;
- exercise connect success, refusal, timeout, EOF, partial read/write,
  cancellation, and backpressure;
- verify address and error normalization at the seam.

Use Go loopback sockets first, then use two wasm core instances to complete the
smallest meaningful EasyTier handshake over the Adapter path.

### P0.3: UDP and minimal network formation

- implement bind, send, receive, close, and peer-scoped UDP session behaviour;
- exercise datagram truncation policy, zero-length datagrams, multiple peers,
  cancellation, and receive backpressure;
- connect two core instances with a minimal configuration that needs no native
  TUN and show peer admission, route convergence, and packet exchange through a
  host-provided packet Interface.

If current core ownership prevents this scenario, add only the smallest
experiment seam required to expose the scheduling question. Record the missing
ownership as Phase 1 or Phase 2 work instead of pulling the whole refactor into
the PoC.

### P0.4: lifecycle and measurement

- repeat start/stop and forced host-operation failure;
- leave operations pending during graceful stop and verify cleanup ordering;
- hard-kill a deliberately stuck instance without corrupting the other module;
- measure timer delay, idle CPU, throughput, allocations, queue depth, and
  shutdown latency for each viable runtime model.

## Acceptance gates

The PoC passes only if all gates pass.

### Correctness

- two Go-hosted core instances form a peer connection and exchange packets;
- DNS, TCP, UDP, timers, and cancellation all traverse the intended seams;
- one pending operation cannot prevent unrelated work;
- errors and EOF are distinguishable and do not leak Go handles.

### Scheduling and performance

- the drive loop has no unconditional busy polling;
- under the pending-read scenario, timer p99 delay is no worse than twice the
  native current-thread baseline plus 5 ms in the same controlled test;
- idle CPU for one quiescent instance is below 1% of one core after warm-up, or
  the result is rejected with evidence that the measurement floor is higher;
- packet throughput reaches at least 50% of the equivalent native Adapter path
  before optimization, with profiling showing no architectural serialization
  beyond the required single drive owner;
- queue depth remains bounded under sustained producer pressure.

These are PoC gates, not production performance promises. Record the native
baseline and environment before comparing models; do not weaken a gate after a
failed result without documenting why the measurement was invalid.

### Lifecycle and isolation

- cooperative stop completes within two seconds after Go cancels all pending
  host operations;
- 100 create/start/stop cycles leave no growing goroutine, operation-handle, or
  wasm-memory count;
- separate module instances do not share configuration, DNS results, handles,
  peer state, or cancellation;
- module close can terminate a stuck instance as a hard-kill fallback.

### Memory and ABI

- memory growth does not invalidate data retained by Go;
- malformed lengths, handles, encodings, and duplicate Completions fail safely;
- every allocated cross-boundary buffer has one documented owner and release
  point;
- the wasm import list contains only the intended WASI and host capabilities.

## Deliverables and decision

Phase 0 produces:

1. a small reproducible Go harness and wasm build command;
2. conformance tests for the selected scheduling and operation model;
3. measurements for Models B and, only if necessary, C;
4. an ADR fixing drive ownership, wake behaviour, batch encoding, memory
   ownership, cancellation, and error semantics;
5. an explicit go/no-go decision for using Tokio plus wazero as the production
   Go-host model.

If the PoC fails, decide among changing the drive model, changing the wasm
runtime, or introducing a core executor seam. Do not respond by moving portable
network logic back into the host.

## Reproduction baseline

The already verified test shape is:

```sh
cargo test -p easytier-core --target wasm32-wasip1 --no-run
cargo test -p easytier-core --target wasm32-wasip1 --no-default-features --no-run
cargo test -p easytier-core --target wasm32-wasip1 --all-features --no-run
go run github.com/tetratelabs/wazero/cmd/wazero@v1.12.0 run <test-artifact>.wasm
```

The PoC must pin the Rust toolchain, Cargo feature set, wazero version, Go
version, and artifact hash in its result.

## Primary references

- [Tokio wasm support](https://docs.rs/tokio/1.52.1/src/tokio/lib.rs.html#424-455)
- [Tokio current-thread runtime behaviour](https://tokio.rs/tokio/topics/bridging)
- [wazero concurrency guidance](https://wazero.io/languages/)
- [wazero Function.Call contract](https://pkg.go.dev/github.com/tetratelabs/wazero/api#Function)
- [Rust `wasm32-wasip1` target](https://doc.rust-lang.org/nightly/rustc/platform-support/wasm32-wasip1.html)
- [wazero host functions](https://pkg.go.dev/github.com/tetratelabs/wazero#HostFunctionBuilder)

