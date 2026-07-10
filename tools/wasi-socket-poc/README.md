# Go/WASI Socket PoC

This experiment answers the first Phase 0 socket questions from
[`go_wasi_host_poc.md`](../../refactor-doc/go_wasi_host_poc.md): can a Go host
create a connection and let a current-thread Tokio guest drive asynchronous
read/write without blocking unrelated work, either through a WASI virtual fd or
an opaque host handle?

The experiment deliberately uses a separate Rust guest instead of
`easytier-core`. This keeps Tokio/wazero capability failures separate from the
ongoing EasyTier ownership migration.

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

The opaque-handle probe then tests a deliberately small host Interface:

- Go holds two arbitrary logical `net.Conn` values in a handle table;
- the guest's `AsyncRead` and `AsyncWrite` implementations submit operations
  only when Tokio polls them;
- Go executes the requested `net.Conn.Read` or `net.Conn.Write` in goroutines and
  records owned completion data;
- the host serially re-enters one bounded guest `drive` after an I/O completion
  or a 5 ms timer tick;
- one `net.Pipe` read remains pending while another `net.Pipe` echoes data and a
  Tokio timer advances.

This slice does not add a wazero fork and does not modify `easytier-core`.

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
- a permanently pending read does not block a second connection or a 50 ms
  Tokio timer;
- all guest calls remain serialized. Go I/O workers never re-enter the module.

The observed test completes with status `0x1b`: timer progress, second-socket
progress, pending-read isolation, and completion. The exact drive-call count is
timing-dependent.

This proves functional scheduling, not the production wake strategy. The 5 ms
tick is only a PoC mechanism for advancing Tokio timers. Before selecting the
bounded-drive design, core must export its next timer deadline (or provide one
central wait) so an idle instance does not poll periodically. UDP, partial I/O,
cancellation, EOF, sustained backpressure, and lifecycle remain later P0.2
work.
