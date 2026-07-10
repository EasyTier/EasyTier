# Go/WASI Socket PoC

This experiment answers the first Phase 0 question from
[`go_wasi_host_poc.md`](../../refactor-doc/go_wasi_host_poc.md): can a Go host
create a TCP resource and let a current-thread Tokio guest drive asynchronous
read/write through WASIp1 without blocking unrelated work?

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

The current slice tests wazero's public pre-opened TCP listener support:

- the guest takes ownership of WASI virtual fd 3;
- one accepted connection remains blocked in `read`;
- a second connection must still echo data;
- Tokio timers must continue;
- the host counts `poll_oneoff` calls to detect busy polling;
- the test records the public wazero socket configuration methods.

Dynamic injection of an arbitrary Mihomo `net.Conn`, logical connection wrapper,
and UDP resource are capability questions, not implemented fallbacks in this
slice. The experiment must not add a wazero fork or an opaque-handle Interface
until the public virtual-fd result is recorded.

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
decision is whether to maintain a wazero extension for dynamic resources and
socket readiness or to make the opaque-handle Model B the primary experiment.
