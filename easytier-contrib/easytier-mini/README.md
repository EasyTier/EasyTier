# easytier-mini

`easytier-mini` is a native EasyTier POC binary. It shares EasyTier's TOML
configuration model, peer protocol, TCP/UDP tunnel implementations, TUN,
dynamic IPv4 allocation, the smoltcp userspace path and STUN/UDP hole-punching
core with the full binary. It includes AES-GCM so its default encryption
setting interoperates with the full binary's default configuration.

Build it with:

```sh
cargo build --release -p easytier-mini
```

For the static size target used by this POC:

```sh
cargo build --profile mini --target x86_64-unknown-linux-musl -p easytier-mini
```

MIPS targets use the repository's existing musl-cross toolchains. The helper
builds the standard library for size, applies immediate-abort only to the mini
MIPS target graph, and can build either or both byte orders:

```sh
./easytier-contrib/easytier-mini/build-mips.sh all
./easytier-contrib/easytier-mini/build-mips.sh mips
./easytier-contrib/easytier-mini/build-mips.sh mipsel
```

The `mini` profile derives from `release` and applies `opt-level=z` to the
entire compact binary dependency graph. Full EasyTier release builds retain
their normal `opt-level=3` profile. The musl builds use a mini-only static
linker policy to stay below 5,000,000 bytes on x86-64 and 5,500,000 bytes on
MIPS without UPX or another executable compressor. The compact x86-64 linker
policy retains static PIE, packs relative relocations and folds identical code.
MIPS builds omit standard-library backtrace support and use immediate abort;
normal workspace MIPS builds are not affected. Compact linker policies omit
unwind tables.

Start it with a normal EasyTier TOML file:

```sh
easytier-mini --config mini.toml
```

`-c` is accepted as the short form of `--config`.

Start it as an EasyTier Web managed node with a complete config-server URL:

```sh
easytier-mini --config-server udp://config-server.easytier.cn:22020/TOKEN
```

`--machine-id`, `--hostname`, and `--secure-mode` match the full client's Web
identity and transport options. `--config` and `--config-server` may be used
together: the local instance remains static while Web-owned instances are
created, updated, retained, and deleted independently.

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

Local TOML files accept only `tcp://` and `udp://` listener, mapped-listener
and peer URLs. They reject unsupported VPN Portal, SOCKS, port forwarding,
proxy networks, exit-node gateway, Magic DNS, KCP, QUIC, compression, ChaCha20,
socket mark and UDP broadcast relay settings. The standard `no_tun` and
`use_smoltcp` flags are accepted; `no_tun = true` runs through smoltcp without
an OS TUN device.
Set `dhcp = true` to allocate the virtual IPv4 address dynamically.

Web configuration is deliberately handled differently. The complete
authoritative configuration is retained without feature stripping and returned
canonically through the Web management/config RPCs so easytier-web consistency
checks can converge.
Unsupported capabilities are disabled only in a detached runtime projection,
with a warning logged once for each suppressed capability category. This also
applies to hot patches: for example, a Web port-forward patch remains visible
to the controller while no port-forward service is started by mini. ChaCha20
is projected to AES-GCM rather than plaintext.

The mini feature set keeps STUN collection, UDP hole punching, Web heartbeats,
Web instance lifecycle management and the config hot-patch RPC. It omits TCP
hole punching, endpoint discovery (`http://`, `https://`, `txt://` and
`srv://` peers), protobuf reflection, logger control and the rest of the full
management surface. Its local RPC surface remains read-only for node, peer,
route and connector queries. OSPF route messages keep their original protobuf
wire data, so fields added by future EasyTier versions are forwarded without
requiring `prost-reflect`.

For size, this POC reads one file directly and does not support configuration
from stdin or `${VAR}` expansion. It also omits the tracing subscriber and the
process-management event journal. `socket_mark` is rejected because the compact
DNS path cannot apply marks to resolver sockets. Startup and fatal errors are
still written to stderr. The RPC address is currently fixed, so only one mini
process can use the default portal on a host. The x86-64 musl POC cannot
provide reliable stack backtraces because its release binary has no unwind
tables.
