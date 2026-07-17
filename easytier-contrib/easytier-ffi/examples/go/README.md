# 1. Go FFI Demo

This demo wraps EasyTier FFI data-plane TCP as Go `net.Conn` and `net.Listener`.
It can connect to an SSH server through EasyTier and read its banner, or accept a
TCP connection from another EasyTier peer and run a small ping/pong exchange.
The async op-handle wrapper is in `easytier_async.go`; the original synchronous
wrapper stays in `easytier.go`.

## 1.1. Build the FFI library

Run from the repository root:

```sh
cargo build -p easytier-ffi --features ffi-dataplane
```

The demo loads the debug library by default:

```text
target/debug/libeasytier_ffi.so
```

To use another library path, export `EASYTIER_FFI_LIB=/path/to/libeasytier_ffi.so`.

## 1.2. Configure the EasyTier config

`EASYTIER_FFI_CONFIG` is a string of the EasyTier config in TOML format which is passed to the FFI library. For example:

```sh
export EASYTIER_FFI_CONFIG='instance_name = "default"
ipv4 = "10.0.0.1"

[network_identity]
network_name = "testnet"
network_secret = "mysecret"

[flags]
no_tun = true # disable tun device to avoid permission issues.
bind_device = false # allow loopback peers in local examples.

[[peer]]
uri = "tcp://123.123.123.123:11010"
'
```

You should configure with your own real values.

Set the local instance name and a SSH server target to connect through EasyTier:

```sh
export EASYTIER_FFI_INSTANCE=default
export EASYTIER_FFI_TARGET=10.0.0.2:22
```

To run the TCP listen integration test in the same `go test` process as the SSH
test, use a separate instance name and config:

```sh
export EASYTIER_FFI_LISTEN_CONFIG='instance_name = "listener"
ipv4 = "10.0.0.3"

[network_identity]
network_name = "testnet"
network_secret = "mysecret"

[flags]
no_tun = true
bind_device = false

[[peer]]
uri = "tcp://123.123.123.123:11010"
'
export EASYTIER_FFI_LISTEN_INSTANCE=listener
export EASYTIER_FFI_LISTEN_PORT=12345
```

## 1.3. Run the demo

`goffi` is built without cgo on Linux, so run the tests with `CGO_ENABLED=0`:

```sh
cd easytier-contrib/easytier-ffi/examples/go
CGO_ENABLED=0 go test -v ./...
```

The synchronous tests use the environment variables above. The async Go tests
are self-contained: they start two local EasyTier instances in the same test
process with `no_tun = true` and `bind_device = false`, then run TCP and UDP
ping/pong over the async data-plane API.

The synchronous wrapper also exposes `CallJSONRPC(service, method, domain,
payload)` for non-lifecycle EasyTier RPCs. For example,
`CallJSONRPC("api.logger.LoggerRpcService", "get_logger_config", "", "{}")`
returns the logger config as protobuf JSON. Instance lifecycle management RPCs
are intentionally filtered; use the dedicated FFI APIs for starting and
stopping instances.

To run only the async tests:

```sh
cd easytier-contrib/easytier-ffi/examples/go
CGO_ENABLED=0 go test -run 'TestAsync' -v ./...
```

When the SSH integration environment variables are set, expected synchronous
test output includes an SSH banner similar to:

```text
attempt 1: got banner "SSH-2.0-..."
PASS
```

For `TestTCPListenIntegration`, connect from another EasyTier peer to the local
EasyTier IPv4 address and `EASYTIER_FFI_LISTEN_PORT`, send `ping`, and expect
`pong` in response.

The async test output should include local TCP bind/connect log lines and finish
with `PASS` without any extra environment variables.

## 1.4. C async example

The C async example is kept separate from the basic C example:

```sh
cargo build -p easytier-ffi --features ffi-dataplane
cc -Wall -Wextra -pedantic \
  ../example_data_plane_async.c \
  -L ../../../../target/debug -leasytier_ffi \
  -Wl,-rpath,../../../../target/debug \
  -o /tmp/easytier_data_plane_async

/tmp/easytier_data_plane_async
```

Without environment variables it prints usage and exits successfully. With
`EASYTIER_FFI_CONFIG`, `EASYTIER_FFI_INSTANCE`, and one of
`EASYTIER_FFI_TARGET`, `EASYTIER_FFI_LISTEN_PORT`, or `EASYTIER_FFI_UDP_TARGET`,
it runs the corresponding async data-plane flow.
