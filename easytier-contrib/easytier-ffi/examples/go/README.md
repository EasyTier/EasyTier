# 1. Go FFI Demo

This demo wraps EasyTier FFI data-plane TCP as Go `net.Conn` and `net.Listener`.
It can connect to an SSH server through EasyTier and read its banner, or accept a
TCP connection from another EasyTier peer and run a small ping/pong exchange.

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
peers = ["tcp://123.123.123.123:11010"]

[network_identity]
network_name = "testnet"
network_secret = "mysecret"

[flags]
no_tun = true # disable tun device to avoid permission issues.
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
peers = ["tcp://123.123.123.123:11010"]

[network_identity]
network_name = "testnet"
network_secret = "mysecret"

[flags]
no_tun = true
'
export EASYTIER_FFI_LISTEN_INSTANCE=listener
export EASYTIER_FFI_LISTEN_PORT=12345
```

## 1.3. Run the demo

`goffi` is built without cgo on Linux, so run the test with `CGO_ENABLED=0`:

```sh
cd easytier-contrib/easytier-ffi/examples/go
CGO_ENABLED=0 go test -v ./...
```

Expected output includes an SSH banner similar to:

```text
attempt 1: got banner "SSH-2.0-..."
PASS
```

For `TestTCPListenIntegration`, connect from another EasyTier peer to the local
EasyTier IPv4 address and `EASYTIER_FFI_LISTEN_PORT`, send `ping`, and expect
`pong` in response.
