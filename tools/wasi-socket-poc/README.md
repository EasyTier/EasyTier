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
- the host serially re-enters one bounded guest `drive` after an I/O completion
  or a 5 ms timer tick;
- one `net.Pipe` read remains pending while another `net.Pipe` echoes data and a
  Tokio timer advances.

The UDP probe uses the same core reactor with `HostUdpSocket` and
`WasiHostUdpIo`:

- Go owns a real `net.PacketConn` behind an opaque handle;
- receive workers queue owned datagrams, while only a guest `take_udp_recv`
  poll removes one, preserving Tokio cancellation semantics;
- `try_udp_send` synchronously copies one complete datagram into a bounded Go
  queue; writable waits do not enqueue data and are cancel-safe;
- a fixed 44-byte network-order ABI carries IPv4/IPv6 peer addresses, port,
  IPv6 flow/scope, and optional source or destination IP metadata;
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

This slice does not add a wazero fork. Its 5 ms drive loop remains test-only
rather than becoming part of `easytier-core`.

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
- all guest calls remain serialized. Go I/O workers never re-enter the module.

The observed test completes with status `0x1b`: timer progress, second-socket
progress, pending-read isolation, and completion. The exact drive-call count is
timing-dependent.

This proves functional scheduling, host-controlled socket creation, and reuse
of the real core TCP/UDP Socket Adapters, not the production wake strategy. The
5 ms tick is only a PoC
mechanism for advancing Tokio timers. Before selecting the bounded-drive
design, core must export its next timer deadline (or provide one central wait)
so an idle instance does not poll periodically. Forced TCP partial I/O, UDP
zero-length/truncation and cancellation through wazero, sustained backpressure,
multiple UDP peers, and complete instance lifecycle remain later P0.2 work.
