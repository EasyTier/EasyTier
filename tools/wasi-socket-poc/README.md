# Go/WASI Socket PoC

This experiment answers the first Phase 0 socket questions from
[`go_wasi_host_poc.md`](../../refactor-doc/go_wasi_host_poc.md): can a Go host
create a connection and let a current-thread Tokio guest drive asynchronous
read/write without blocking unrelated work, either through a WASI virtual fd or
an opaque host handle?

The experiment uses a small standalone Rust guest that depends on
`easytier-core`. The public-fd probe isolates Tokio/wazero capabilities, while
the opaque-handle probe exercises the real core Socket Adapter without pulling
in a complete EasyTier instance.

## Run

Requirements:

- Rust 1.95 with the `wasm32-wasip1` target;
- Go 1.25 or newer;
- no cgo.

```sh
cd tools/wasi-socket-poc/host
go test -v ./...
```

The Go test builds the Rust guest automatically and pins Tokio 1.52.1 and
wazero 1.12.0.

## Scope

The public-fd probe tests wazero's pre-opened TCP listener support:

- the guest takes ownership of WASI virtual fd 3;
- one accepted connection remains blocked in `read`;
- a second connection must still echo data;
- Tokio timers must continue;
- the host counts `poll_oneoff` calls to detect busy polling;
- the test records the public wazero socket configuration methods.

The opaque-handle probes then test a deliberately small host Interface:

- Go holds two arbitrary logical `net.Conn` values in a handle table;
- the guest uses `easytier-core`'s `HostSocketRuntime`, `HostTcpStream`, and
  `WasiHostTcpIo` rather than a PoC-only socket implementation;
- `HostTcpStream` submits a demand-driven read or one bounded, owned write-all
  operation when Tokio polls it, and `flush` observes asynchronous write
  completion;
- Go executes the requested `net.Conn.Read` or `net.Conn.Write` in goroutines and
  records owned completion data;
- the standalone socket probe serially re-enters one bounded guest `drive`
  after an I/O completion or a test-only 5 ms timer tick;
- one `net.Pipe` read remains pending while another `net.Pipe` echoes data and a
  Tokio timer advances.

The UDP probe uses the same core reactor with `HostUdpSocket` and
`WasiHostUdpIo`:

- Go owns a real `net.PacketConn` behind an opaque handle;
- receive workers queue owned datagrams, while only a guest `take_udp_recv`
  poll removes one, preserving Tokio cancellation semantics;
- `try_udp_send` synchronously copies one complete datagram into a bounded Go
  queue; writable waits do not enqueue data and are cancel-safe;
- a fixed 48-byte network-order ABI carries IPv4/IPv6 peer addresses, port,
  IPv6 flow/scope, optional source or destination IP metadata, and an IPv6
  source-interface index;
- the real core socket receives and echoes `udp`; Go performs only
  `ReadFrom`/`WriteTo` and queue bookkeeping.

The factory and listener probes then remove the pre-created-handle shortcut:

- core forwards versioned `TcpConnectOptions`, `UdpBindOptions`, and
  `TcpListenOptions` records to one `WasiHostSocketBackend`;
- Go creates the real TCP connection, UDP socket, and TCP listener, then
  returns high-bit opaque handles with their actual local/peer addresses;
- accepted connections remain in a Go listener queue until core polls
  `accept`, so canceling a waiter cannot consume an accepted stream;
- the created/accepted resources complete TCP, UDP, and listener echoes through
  the same core-owned I/O and protocol boundary.

The DNS probe uses the same operation reactor without adding a blocking import:

- core submits address, TXT, and SRV queries with IP-version, socket-mark, and
  netns context;
- Go copies the query, runs an explicitly injected resolver, and retains an
  owned result until the guest performs a bounded two-step take;
- the first lookup is held pending until Tokio registers its waker, and every
  later guest drive requires a host completion signal;
- TXT record/chunk and UTF-8 normalization belong to the injected resolver;
  the PoC deliberately has no `net.DefaultResolver` fallback with different
  semantics.

The packet-egress probe uses a real `HostPacketSink` with a capacity-one Go
queue. The first packet fills the queue, the second write waits only for
writable readiness, and Go consumption emits the completion that admits the
second packet. The test verifies FIFO payloads and waiter cleanup; Go does not
parse or route the packets.

The environment probe drives the real
`HostConnectorEnvironmentServiceAdapter<WasiHostConnectorEnvironmentIo>`:

- Go supplies local-route selection plus UDP and TCP port-mapping operations;
- every operation is forced through Pending, host completion, guest notify,
  and owned result consumption;
- cancellation removes host ownership before cancelling the worker, so a late
  result cannot reappear.

The lifecycle and minimal-network probes use the actual release
`easytier_core.wasm` artifact rather than the small guest wrapper:

- Go passes a normalized, versioned JSON config through guest-owned buffers;
- `create`, `start`, bounded `drive`, `stop`, and `drop` use the exported core
  lifecycle ABI;
- the host waits for an I/O completion or the exact value returned by
  `easytier_instance_next_deadline_millis`; there is no periodic drive tick;
- two isolated wazero runtimes and Go bridges form a raw-TCP EasyTier peer
  connection, converge a route, and deliver an injected IPv4 packet through
  the other instance's host packet sink;
- the server binds port zero through Go, and the client receives the actual
  host-created listener port without a reserve-and-release race;
- cooperative shutdown removes every Go-owned TCP handle and listener.

This slice does not add a wazero fork. The legacy standalone socket probe's
5 ms loop remains test-only; complete core instances use exported deadlines.

## Result with wazero 1.12.0

The public virtual-fd path is not sufficient for Tokio-driven TCP I/O:

- the Rust guest compiles with `tokio_unstable`, `tokio::net`, and
  `wasm32-wasip1`;
- wazero exposes only `WithTCPListener` on its public socket configuration; it
  cannot inject an arbitrary Mihomo `net.Conn` or UDP resource;
- the guest can take virtual fd 3 and register it with Tokio, but Tokio's first
  I/O-driver poll aborts because wazero returns WASIp1 `ENOTSUP` (58);
- the pending-read, second-socket, timer, and idle-polling scenarios therefore
  cannot run on unmodified public wazero 1.12.0.

The test treats this exact limitation as a successful capability probe and
prints a JSON report. An unexpected build, ABI, or runtime failure still fails
the test.

Conclusion: Model A is rejected for unmodified public wazero 1.12.0. The next
experiment is the opaque-handle Model B rather than a wazero extension.

## Opaque-handle result

The minimal Model B path works with wazero 1.12.0:

- it accepts `net.Pipe`, proving the host resource need not expose a raw OS fd;
- Tokio initiates each read/write by polling the guest Socket Adapter;
- Go only performs the requested logical `net.Conn` operation and reports its
  completion; it does not implement framing or protocol state;
- operation IDs are unique across socket runtimes in one wasm module and read
  completions are owned by core; core conformance tests separately cover stream
  cancellation and close;
- a permanently pending read does not block a second connection or a 50 ms
  Tokio timer;
- the same wasm artifact imports both TCP and UDP adapters, and a Go-created
  `net.PacketConn` completes a core-driven UDP echo with the peer address
  preserved;
- Rust and Go share an independently asserted golden UDP metadata vector;
- connect, bind, listen, and accept are requested by core rather than injected
  into probe initialization;
- address, TXT, and SRV resolution is requested through core's injected DNS
  Interface, including host policy metadata and deterministic completion wakes;
- local-route and port-mapping services use the same owned asynchronous host
  operation model;
- packet egress preserves core ordering across bounded Go-host backpressure;
- two real core modules complete TCP peer admission, route convergence, packet
  exchange, and cooperative resource cleanup;
- all guest calls remain serialized. Go I/O workers never re-enter the module.

The observed test completes with status `0x1b`: timer progress, second-socket
progress, pending-read isolation, and completion. The exact drive-call count is
timing-dependent.

This proves the functional bounded-drive strategy, host-controlled
socket/DNS/environment resources, bounded packet egress, and reuse of the real
core Adapters. Complete core instances export their next timer deadline, so an
idle Go host does not poll periodically. Remaining PoC work is measurement and
failure-depth coverage: forced TCP partial I/O, UDP zero-length/truncation,
sustained backpressure, multiple UDP peers, repeated lifecycle failure cases,
hard kill isolation, and latency/resource accounting.
