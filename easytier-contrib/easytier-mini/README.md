# easytier-mini

`easytier-mini` is a native EasyTier POC binary. It shares EasyTier's TOML
configuration model, peer protocol, TCP/UDP tunnel implementations, TUN and
STUN/UDP hole-punching core with the full binary.
It includes AES-GCM so its default encryption setting interoperates with the
full binary's default configuration.

Build it with:

```sh
cargo build --release -p easytier-mini
```

For the static size target used by this POC:

```sh
cargo build --profile mini --target x86_64-unknown-linux-musl -p easytier-mini
```

MIPS targets use the repository's existing musl-cross toolchains and build the
standard library from source:

```sh
RUSTC_BOOTSTRAP=1 cargo build --profile mini \
  --target mips-unknown-linux-musl \
  -Z build-std=std,panic_abort -p easytier-mini
RUSTC_BOOTSTRAP=1 cargo build --profile mini \
  --target mipsel-unknown-linux-musl \
  -Z build-std=std,panic_abort -p easytier-mini
```

The `mini` profile derives from `release` and applies `opt-level=z` to the
entire compact binary dependency graph. Full EasyTier release builds retain
their normal `opt-level=3` profile. The musl builds use a mini-only static
linker policy to stay below 5,000,000 bytes without UPX or another executable
compressor. The compact x86-64 linker policy retains static PIE, packs relative
relocations and folds identical code. Because compact builds use
`panic=abort`, the x86-64 and MIPS linker policies omit unwind tables.

Start it with a normal EasyTier TOML file:

```sh
easytier-mini --config mini.toml
```

`-c` is accepted as the short form of `--config`.
The node also exposes the native EasyTier management RPC protocol on
`127.0.0.1:15888`, so the full `easytier-cli` can inspect it:

```sh
easytier-cli node info
easytier-cli peer
easytier-cli route
easytier-cli connector list
```

For example:

```toml
instance_name = "mini"
ipv4 = "10.147.0.2"
listeners = ["tcp://0.0.0.0:11010", "udp://0.0.0.0:11010"]

[network_identity]
network_name = "mini-poc"
network_secret = "change-me"

[[peer]]
uri = "tcp://example.net:11010"
```

Only `tcp://` and `udp://` listener, mapped-listener and peer URLs are
accepted. The binary has no UPnP/NAT-PMP adapter and forces `disable_upnp`.
It rejects VPN Portal, SOCKS, port forwarding, proxy networks, smoltcp/gateway,
Magic DNS, KCP, QUIC and UDP broadcast relay configuration.

The mini feature set keeps STUN collection and UDP hole punching, but omits
TCP hole punching, endpoint discovery (`http://`, `https://`, `txt://` and
`srv://` peers), protobuf reflection, and the writable or web-facing parts of
the management API. Its compact RPC surface supports read-only node, peer,
route and connector queries; configuration updates, logger control and web
management are not registered. OSPF route messages keep their original
protobuf wire data, so fields added by future EasyTier versions are forwarded
without requiring `prost-reflect`.

For size, this POC reads one file directly and does not support configuration
from stdin or `${VAR}` expansion. It also omits the tracing subscriber and the
process-management event journal. `socket_mark` is rejected because the compact
DNS path cannot apply marks to resolver sockets. Startup and fatal errors are
still written to stderr. The RPC address is currently fixed, so only one mini
process can use the default portal on a host. The x86-64 musl POC cannot
provide reliable stack backtraces because its release binary has no unwind
tables.
