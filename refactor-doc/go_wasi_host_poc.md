# Go Host and WASI Core Phase 0 PoC

> Status: active Phase 0 design. Updated 2026-07-10.

## Question to answer

Can a pure-Go host, initially wazero, create and authorize every DNS and socket
resource while a `wasm32-wasip1` build of the single `easytier-core` crate keeps
current-thread Tokio in control of asynchronous read/write scheduling,
backpressure, timers, and EasyTier protocol state?

The PoC must answer this before the rest of the refactor depends on a particular
socket reference, readiness mechanism, or executor-drive Implementation.

## Ownership under test

The PoC preserves this split:

```text
Go / Mihomo Host Adapter
    DNS, dial, listen, bind, accept, platform policy, real resources
                         |
                         v
              host-backed Socket Interface
                         |
                         v
easytier-core / Tokio
    read/write scheduling, backpressure, framing, protocol lifecycle
```

Every actual OS read, write, poll, and close still executes through WASI or a
Host Adapter. "Tokio-driven I/O" means that core decides when work is polled and
how it participates in EasyTier tasks; it does not mean wasm directly performs
host syscalls.

## What is already proven

At baseline commit `40fb39b5`:

- `easytier-core` builds for `wasm32-wasip1` with default, no-default, and
  all-features configurations;
- pure-Go wazero 1.12.0 executes 220 default/no-default tests and 239
  all-features tests successfully;
- the observed WASI imports include clock, random, and polling facilities;
- the core Tokio feature set is `sync`, `macros`, `io-util`, `rt`, and `time`,
  which is within Tokio's documented stable wasm support.

Tokio 1.52 also documents unstable `tokio::net` support for `wasm32-wasi`.
Because WASIp1 cannot create a new socket inside the guest, such a socket must
be supplied through `FromRawFd`.

This proves compilation and finite test execution. It does not prove that:

- wazero can dynamically register a Mihomo-created `net.Conn` or
  `net.PacketConn` as a guest virtual fd;
- wazero's WASIp1 polling can provide correct and efficient TCP and UDP
  readiness to Tokio;
- a logical Go connection wrapper can be represented by a virtual fd;
- a long-lived Tokio networking instance can idle, wake, and stop correctly.

### Public wazero socket probe result

The reproducible harness in
[`tools/wasi-socket-poc`](../tools/wasi-socket-poc/README.md) tested the public
wazero 1.12.0 path:

- the `tokio_unstable` WASI guest compiles and takes ownership of a pre-opened
  TCP listener virtual fd;
- wazero's public socket configuration exposes only `WithTCPListener`, with no
  arbitrary Go `net.Conn` or UDP resource injection;
- Tokio aborts in its I/O driver when the first WASIp1 `poll_oneoff` returns
  `ENOTSUP` (58).

Consequently Model A is not viable with unmodified public wazero 1.12.0. The
pending-read, second-socket, timer, and idle-polling scenarios cannot be measured
through that path. Phase 0 therefore continues with Model B rather than a wazero
extension.

### Opaque-handle probe result

The same harness now contains a minimal Model B implementation that uses the
real host-backed TCP and UDP Socket Modules in `easytier-core`:

- Go stores arbitrary `net.Conn` values behind opaque integer handles;
- core `HostTcpStream` implements Tokio `AsyncRead` and `AsyncWrite`, while a
  WASI Adapter maps its demand-driven operations to host imports;
- the Adapter submits at most one operation per direction when Tokio polls it;
- Go workers mechanically call the requested `net.Conn.Read` or complete a
  `net.Conn.Write` loop, own every buffer while the guest is not running, and
  signal a completion without re-entering wasm;
- the host serially invokes a bounded guest `drive`, which wakes the registered
  tasks and lets current-thread Tokio poll them again.

For UDP, the Host Adapter keeps datagrams in a per-socket receive queue until a
guest poll removes one. Sends are synchronously copied into a bounded host queue
from the guest poll; when that queue is full, core waits only for writable
readiness. This preserves Tokio's `send_to` and `recv_from` cancellation
semantics without blocking the guest or retaining guest-memory borrows. The
WASI ABI uses an independently golden-tested 44-byte metadata record for peer
address, port, IPv6 flow/scope, and optional source or destination IP.

The same unified backend now implements the existing core socket factories and
TCP listener Interface. Core sends versioned connect/bind/listen options; Go
creates the real resources and returns fixed handle/address records. Accepted
connections remain queued in Go until a core `accept()` poll takes one. The
reproducible probes complete TCP connect, UDP bind, TCP listen/accept, and all
three echo paths without passing pre-created handles into guest initialization.

The integration harness now also uses core's real host-backed DNS and packet
Interfaces. Address, TXT, and SRV queries cross a nonblocking, versioned ABI
with IP-version, socket-mark, and netns context. The Go host must inject a DNS
Implementation that normalizes TXT semantics before the seam; the PoC does not
hide Go/native record-chunk differences behind a default resolver. Variable DNS
results use a non-consuming size probe followed by one bounded owned copy, and
rejected results are canceled explicitly.

The host create schema is version 12 and submits one normalized peer snapshot,
the UDP, TCP, and IPv6 UDP STUN server lists, and core-owned gateway runtime
configuration in connectivity configuration.
Connector route probes also receive the complete socket context. The Go
environment does not construct or expose STUN state, NAT type, public endpoints,
or UDP/TCP STUN mappings; `CoreInstance` builds and drives its portable STUN
collector through the same host-created socket and DNS Interfaces.
Version 12 submits URL-level listener configuration, IPv6 policy, and socket
context. Core derives Ring identity, scheme classification, and internal
TCP/UDP listener requests. Host-submitted running listeners remain absent
because every listener publishes into the core-owned registry. EasyTier-managed
IPv6 addresses are likewise core policy rather than a host environment field.

Packet egress uses a capacity-one Go queue. A successful import owns a complete
packet copy, queue-full has no side effects, and core retries only after a
writable-readiness completion. The deterministic probe proves FIFO delivery,
backpressure, and waiter cleanup without moving packet parsing or routing into
Go. Packet ingress already enters portable logic through
`CoreInstance::send_ip_packet`; exporting the serialized instance command is a
later composition step.

The probe uses two `net.Pipe` connections, so success does not depend on an OS
descriptor. One read remains permanently pending while the second connection
echoes a byte and a 50 ms Tokio timer completes. The observed status `0x1b`
proves timer progress, second-connection progress, pending-read isolation, and
successful completion. All wasm calls remain serialized.

This answers the ownership question precisely: Tokio can keep control of when
EasyTier tasks request and observe I/O, while Go performs the unavoidable
mechanical call on the logical `net.Conn` or `net.PacketConn`. Go does not need
to own framing, sessions, protocol state, retries, or routing.

Some socket/timer probes still use a 5 ms tick in addition to completion wakes.
The DNS and packet-backpressure probes require completion signals and do not use
that tick. No periodic tick is an accepted idle strategy. The PoC has not yet
proven deadline-aware sleeping, idle CPU, the full UDP conformance matrix,
partial TCP I/O, EOF, sustained backpressure, or lifecycle cleanup.

## Constraints

1. Tokio stays internal to core. Tokio runtime handles, tasks, futures, and
   wakers do not cross the host seam.
2. One wasm module instance uses current-thread Tokio. Multi-thread Tokio is not
   part of this design.
3. Go and Mihomo control DNS and every real socket creation. Core cannot bypass
   their routing, loop-prevention, or platform policy.
4. Core owns socket I/O scheduling, backpressure, portable framing, and protocol
   state after the Host Adapter supplies a socket.
5. A wazero guest call runs synchronously on its calling Go goroutine. Calls
   into the same module instance are serialized and never re-entrant.
6. An individual socket or DNS import must not block the only guest executor.
7. Go does not retain a borrowed slice into wasm memory after a call returns.
   Data is copied or represented by an owned resource reference.
8. A logical `net.Conn` or `net.PacketConn` may contain Mihomo behaviour beyond
   an OS descriptor. The selected model must not require unsafe descriptor
   extraction that bypasses that behaviour.
9. Normal cancellation is cooperative. Closing the whole module is reserved for
   a stuck-instance hard kill.
10. The first PoC uses pure Go and no cgo so the embedding and deployment model
    remains representative.

## Candidate socket models

### Model A: injected virtual fd with Tokio-driven I/O

The Go Host Adapter creates a socket with the Mihomo dialer or packet-listener
path and registers it in the module's WASI resource table. Core receives a guest
virtual fd and constructs a Tokio socket through `FromRawFd`. Tokio drives
read/write and readiness through WASI.

This is the preferred model because it most closely matches the native Socket
Interface and keeps the wasm-specific Interface small. It passes the deletion
test: removing the virtual-fd Adapter would force fd ownership, readiness,
error, and cancellation rules into every socket caller.

The PoC must not assume this works. wazero v1.12.0 publicly supports pre-opened
TCP listeners, but does not expose a complete dynamic registration Interface
for arbitrary outbound TCP connections or UDP packet connections. Its WASIp1
polling implementation also needs explicit readiness validation. Record whether
a small maintainable wazero extension can close those gaps.

### Model B: opaque handle with core-driven asynchronous I/O

The Go Host Adapter creates a logical socket and returns an opaque host handle.
A wasm Socket Adapter implements the existing core asynchronous Socket Interface
over submitted host operations and a centralized completion mechanism. Tokio
still decides when each socket is polled and owns task wakeups, backpressure, and
protocol state. For a generic Go `net.Conn`, the submitted operation may execute
on a Go worker because the Interface itself exposes blocking `Read` and `Write`.

This model can preserve arbitrary Go `net.Conn` and `net.PacketConn` wrappers
without modifying wazero's internal fd table. Its cost is a custom readiness and
data-transfer Interface. The Interface must stay deep: individual callers must
not learn host queue, memory, or wakeup details.

### Model C: host-owned queue fallback

Go continuously drives socket I/O into host-owned send and receive queues,
independently of whether Tokio has polled a corresponding operation. A
serialized guest invocation later pushes owned completions to core.

This is a valid portability fallback, not the default ownership model. Unlike
Model B's demand-driven single operations, it gives Go responsibility for queue
policy and backpressure. It therefore needs evidence that Model B is not viable
or is materially worse.

### Model D: blocking per-socket imports

Core calls a host `read`, `write`, `accept`, or resolver operation and that
individual import waits for its result.

Reject this model. One pending operation can freeze unrelated connections,
Tokio timers, cancellation, peer maintenance, and shutdown.

## Candidate executor-drive models

Socket representation and executor progress are separate choices. Test both
where the socket model permits them:

### Long-lived serialized guest call

One Go goroutine enters the guest runtime and remains its sole owner. Tokio idles
inside one centralized host or WASI readiness wait that can wake for any socket,
timer, cancellation request, or external command.

This avoids periodic re-entry but requires a correct multiplexed wait and a
cooperative way to deliver host commands without a concurrent guest call.

### Bounded cooperative drives

Go invokes serialized bounded drives. Each drive lets Tokio make progress and
returns a wake requirement. Go waits for readiness, a timer deadline, or an
external command before starting the next drive.

This keeps lifecycle control explicit but must prove that it can advance Tokio
without unconditional polling or leaking executor details across the seam.

Phase 0 selects one socket model and one executor-drive model. It must not leave
multiple accidental production modes.

## Experiment shape

Use two layers so wazero limitations are not confused with unfinished EasyTier
ownership migration.

### Socket substrate harness

A minimal Rust wasm guest exercises Tokio timers and a host-created socket but
contains no EasyTier protocol logic. It establishes whether virtual fd or opaque
handle readiness works at all.

### EasyTier integration harness

The real `easytier-core` wasm artifact uses the selected experimental Socket and
DNS Adapters. It establishes whether the model composes with the existing core
Socket Interface and protocol tasks.

The Go harness owns resources and policy but does not implement EasyTier
framing, routing, retries, peer state, or protocol lifecycle.

## Milestones

### P0.1: wazero socket capability probe

- build a minimal current-thread Tokio `wasm32-wasip1` guest;
- have Go create a TCP connection and attempt to register it as a guest virtual
  fd without letting the guest dial;
- verify read, partial write, EOF, close, and real readiness through Tokio;
- keep one read pending while a timer and another socket continue;
- test accepted TCP resources and UDP packet resources, not only a pre-opened
  listener;
- repeat with a logical Go connection wrapper whose semantics cannot be reduced
  to a raw OS descriptor;
- document every required unstable Tokio setting, wazero extension, and
  unsupported operation.

Exit P0.1 with one of three results:

1. Model A is viable with public wazero;
2. Model A is viable with a small maintainable extension whose ownership and
   portability are acceptable;
3. Model A is rejected with a reproducible reason, and Model B becomes primary.

### P0.2: opaque-handle comparison

Run this milestone if Model A is rejected or needs comparison before accepting
a wazero extension.

- implement one deep experimental Socket Adapter over opaque Go handles;
- preserve Tokio-owned read/write polling, backpressure, and task wakeups;
- exercise TCP connect, accept, refusal, timeout, EOF, partial I/O,
  cancellation, and sustained backpressure;
- exercise UDP bind, send, receive, source address, zero-length datagrams,
  truncation policy, multiple peers, cancellation, and receive backpressure;
- measure data copies, wakeups, queue depth, idle CPU, and timer delay against
  Model A where available;
- prototype Model C only if Model B cannot provide correct, efficient readiness.

### P0.3: DNS and minimal EasyTier network

> Status: functional gate passed with opaque Model B. Two release
> `easytier_core.wasm` instances use separate Go bridges, create a raw TCP
> listener/connection through the host, complete peer admission and route
> convergence, and exchange an IPv4 packet through host packet Interfaces.
> Address DNS is injected by Go and the scheduler uses exported core deadlines.

- route every hostname lookup through the Go Host Adapter;
- ensure IP literals and non-IP transports do not accidentally invoke DNS;
- instantiate two real core wasm modules with different minimal configurations;
- create every TCP or UDP resource through the Go Host Adapter;
- complete the smallest meaningful EasyTier handshake;
- show peer admission, route convergence, and packet exchange through a
  host-provided packet Interface without a native TUN;
- keep an unrelated socket pending throughout the scenario.

If current core ownership prevents the scenario, add only the smallest
experiment seam required to expose the socket and scheduling question. Record
the missing ownership as Phase 1 or Phase 2 work rather than pulling the whole
refactor into the PoC.

### P0.4: lifecycle and measurement

> Status: basic cooperative lifecycle passed. Go drives create/start/stop/drop
> for real core modules and verifies host TCP handles/listeners are released.
> Repetition, forced failures, hard-kill isolation, and quantitative
> measurements remain open.

- start and cooperatively stop two module instances repeatedly;
- leave DNS and socket resources pending during graceful stop and verify cleanup
  ordering;
- force Host Adapter failures and malformed results;
- hard-kill a deliberately stuck instance without corrupting the other module;
- measure timer delay, idle CPU, throughput, allocations, copies, wakeups,
  resource count, and shutdown latency for every viable model.

## Acceptance gates

The PoC passes only if all gates pass.

### Ownership and correctness

- the Go Host Adapter observes and controls every DNS request and real socket
  creation;
- core cannot create an untracked real socket;
- after socket creation, core and Tokio own read/write scheduling, backpressure,
  framing, and protocol lifecycle;
- the Go harness contains no EasyTier peer, routing, retry, or framing logic;
- two Go-hosted core instances form a peer connection and exchange packets;
- TCP, UDP, DNS, timers, cancellation, EOF, and errors cross their intended
  seams without leaking host resources;
- a logical Go connection wrapper retains its behaviour.

### Scheduling and performance

- no individual DNS, read, write, accept, or receive host call blocks unrelated
  guest work;
- the selected executor-drive model has no unconditional busy polling;
- under the pending-read scenario, timer p99 delay is no worse than twice the
  native current-thread baseline plus 5 ms in the same controlled test;
- idle CPU for one quiescent instance is below 1% of one core after warm-up, or
  the result is rejected with evidence that the measurement floor is higher;
- packet throughput reaches at least 50% of the equivalent native Adapter path
  before optimization, with profiling identifying every unavoidable
  serialization and copy;
- readiness events, buffers, and queues remain bounded under sustained producer
  pressure.

These are PoC gates, not production performance promises. Record the native
baseline and environment before comparing models; do not weaken a gate after a
failed result without documenting why the measurement was invalid.

### Lifecycle and isolation

- cooperative stop completes within two seconds after the host cancels or wakes
  all pending resources;
- 100 create/start/stop cycles leave no growing goroutine, virtual-fd, opaque
  handle, queue, or wasm-memory count;
- separate module instances do not share configuration, DNS results, handles,
  peer state, or cancellation;
- module close can terminate a stuck instance as a hard-kill fallback.

### Memory and resource ownership

- memory growth does not invalidate data retained by Go;
- malformed lengths, resource references, encodings, and duplicate readiness or
  completion events fail safely;
- every virtual fd, opaque handle, buffer, and logical Go connection has one
  documented owner and close point;
- the wasm import list contains only the intended WASI and host capabilities.

## Deliverables and decision

Phase 0 produces:

1. a minimal socket substrate harness and a real-core Go integration harness;
2. a reproducible capability report for Tokio WASI networking and wazero socket
   injection/readiness;
3. conformance tests and measurements for Model A and, when required, Model B;
4. evidence before selecting Model C as a fallback;
5. an ADR fixing socket reference, readiness, executor progress, data ownership,
   cancellation, and error semantics;
6. an explicit go/no-go decision for Tokio-driven socket I/O under the selected
   wazero embedding.

If the PoC fails, decide among maintaining a small wazero extension, using the
opaque-handle Adapter, changing the wasm runtime, or introducing a core executor
seam. Do not respond by moving portable network or protocol logic into Go.

## Reproduction baseline

The already verified test shape is:

```sh
cargo test -p easytier-core --target wasm32-wasip1 --no-run
cargo test -p easytier-core --target wasm32-wasip1 --no-default-features --no-run
cargo test -p easytier-core --target wasm32-wasip1 --all-features --no-run
go run github.com/tetratelabs/wazero/cmd/wazero@v1.12.0 run <test-artifact>.wasm
```

The PoC must pin the Rust toolchain, Cargo feature set, Tokio unstable settings,
wazero version or patch, Go version, and artifact hash in its result.

## Primary references

- [Tokio wasm support](https://docs.rs/tokio/1.52.1/src/tokio/lib.rs.html#424-455)
- [Tokio current-thread runtime behaviour](https://tokio.rs/tokio/topics/bridging)
- [wazero experimental sockets](https://pkg.go.dev/github.com/tetratelabs/wazero/experimental/sock)
- [wazero WASIp1 polling](https://github.com/tetratelabs/wazero/blob/v1.12.0/imports/wasi_snapshot_preview1/poll.go)
- [wazero concurrency guidance](https://wazero.io/languages/)
- [wazero Function.Call contract](https://pkg.go.dev/github.com/tetratelabs/wazero/api#Function)
- [Rust `wasm32-wasip1` target](https://doc.rust-lang.org/nightly/rustc/platform-support/wasm32-wasip1.html)
