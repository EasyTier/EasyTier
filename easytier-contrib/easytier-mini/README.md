# easytier-nano

This fork further reduces the official mini. The default retains encrypted
TCP/UDP mesh connections, transit relay, OS TUN, static IPv4/IPv6, STUN and
UDP hole punching. It shares EasyTier's TOML model and peer protocol.
AES-GCM stays enabled and interoperates with the full binary's defaults.

DHCP, Web management, local RPC, smoltcp, statistics collection and the
console event logger are **not included by default**. Release tracing/log
events and the startup banner are also omitted. Optional features can restore
the capabilities needed by a deployment.

The executable is named `easytier-nano`. The Cargo package and source directory
remain `easytier-mini`, so build commands still use `-p easytier-mini`.

The official, unmodified [pre-built binaries](https://github.com/EasyTier/easytier-mini/releases)
are released from the separate [mini repository](https://github.com/EasyTier/easytier-mini).
The modified binaries described here must be built from this checkout.

## Build

Stable Rust static x86-64 Linux build, with LLVM `ld.lld` installed:

```sh
rustup target add x86_64-unknown-linux-musl
cargo rustc --locked --profile mini --target x86_64-unknown-linux-musl -p easytier-mini -- -C link-arg=-fuse-ld=lld
```

For the smallest static x86-64 Linux build:

```sh
rustup component add rust-src
./easytier-contrib/easytier-mini/build-small.sh
```

This helper requires `protoc`, a C compiler, LLVM `ld.lld` and `readelf`
from binutils. It rebuilds the standard library for size, removes
panic-location metadata and `Debug` formatting, uses immediate abort,
disables unwind tables and compiles release logging out.
The output is `target/x86_64-unknown-linux-musl/mini/easytier-nano`.
It is static PIE with packed relative relocations and identical-code
folding, without UPX or another executable compressor.
The helper verifies the ELF with `readelf` and rejects an interpreter
(`INTERP`) or external shared-library dependency (`NEEDED`).

The standard-library and immediate-abort options require unstable Rust
flags. The helper enables `RUSTC_BOOTSTRAP` only for its invocation on the
pinned toolchain. `-Zfmt-debug=none` applies only to the target crate graph
built by this helper: debug-rendered values in panic or internal error
details can disappear. Explicit startup/configuration errors still use
`Display` formatting and go to stderr. Other workspace builds keep their
usual panic and formatting policy. Use the ordinary Cargo command when
these diagnostic tradeoffs or unstable options are undesirable.

Additional Cargo options can follow the target:

```sh
./easytier-contrib/easytier-mini/build-small.sh x86_64-unknown-linux-musl --features web-client
./easytier-contrib/easytier-mini/build-small.sh x86_64-unknown-linux-musl --features dhcp
```

The default requires a static virtual IP for TUN use; the second command
restores dynamic IPv4 allocation. A relay-only node, with no virtual IP,
can omit `tun` with an ordinary Cargo build:

```sh
cargo rustc --locked --profile mini --target x86_64-unknown-linux-musl -p easytier-mini --no-default-features --features low-memory,strip-logs -- -C link-arg=-fuse-ld=lld
```

MIPS builds retain the existing musl-cross helper, with the same release-log
and panic-location/Debug stripping. Their executable is also
`easytier-nano`. The MIPS helper requires `readelf` and performs the same
`INTERP`/`NEEDED` static-link checks:

```sh
./easytier-contrib/easytier-mini/build-mips.sh all
./easytier-contrib/easytier-mini/build-mips.sh mips
./easytier-contrib/easytier-mini/build-mips.sh mipsel
```

The `mini` profile uses `opt-level=z`, LTO, one codegen unit and stripped
symbols. Full EasyTier release builds keep their normal `opt-level=3`.

## Optional Features

| Feature | Capability |
| --- | --- |
| `tun` | Native virtual interface; default |
| `dhcp` | Dynamic IPv4 allocation |
| `low-memory` | Smaller bounded queues; default |
| `statistics` | Runtime observability counters and traffic recorders |
| `logging` | Console runtime events and warnings |
| `smoltcp` | Userspace stack for `no_tun` and `use_smoltcp` |
| `proxy-cidr-monitor` | Proxy CIDR monitoring and manual routes |
| `rpc` | Read-only native management RPC and statistics |
| `web-client` | Web heartbeats, managed instance lifecycle and patches; includes RPC |
| `strip-logs` | Compile release tracing/log events out and omit startup banner; default |
| `official` | Original mini capabilities and Noise resolver algorithm set |

Restore the original capabilities and queue sizes:

```sh
cargo rustc --locked --profile mini --target x86_64-unknown-linux-musl -p easytier-mini --no-default-features --features official -- -C link-arg=-fuse-ld=lld
```

Restore only DHCP on the stripped default:

```sh
cargo rustc --locked --profile mini --target x86_64-unknown-linux-musl -p easytier-mini --features dhcp -- -C link-arg=-fuse-ld=lld
```

Enable console events while retaining TUN and smaller queues:

```sh
cargo rustc --locked --profile mini --target x86_64-unknown-linux-musl -p easytier-mini --no-default-features --features tun,low-memory,logging -- -C link-arg=-fuse-ld=lld
```

`strip-logs` is additive: combining it with `logging` still strips release
events. Merely adding `--features logging` to the default does not restore
them; omit `strip-logs` as in the recipe above. Both size helpers explicitly
enable `strip-logs`, so use ordinary Cargo for logging-enabled builds.
Startup/configuration errors continue to go to stderr. Build just
`-p easytier-mini`: workspace-wide Cargo feature unification can otherwise
pull full features into nano or apply nano's memory/log policy to other
binaries built together.

## Run

```sh
easytier-nano --config nano.toml
```

`-c` is also accepted. A basic configuration:

```toml
instance_name = "nano"
ipv4 = "10.147.0.2"
listeners = ["tcp://0.0.0.0:11010", "udp://0.0.0.0:11010"]

[network_identity]
network_name = "my-network"
network_secret = "change-me"

[[peer]]
uri = "tcp://example.net:11010"
```

With the `dhcp` feature enabled, set `dhcp = true` instead of `ipv4` for
dynamic allocation. The default reports this setting as an error because
DHCP is omitted. An OS TUN needs the usual administrator privileges.
A relay-only node needs no virtual IP. The default opens no management
port, creates no Web heartbeat tasks and omits management statistics.

With `web-client` enabled:

```sh
easytier-nano --config-server udp://config-server.easytier.cn:22020/TOKEN
```

`--machine-id`, `--hostname` and `--secure-mode` retain the full client's
Web identity/transport meanings. Local and Web configurations can be used
together. Web-owned instances remain independently created, updated and
deleted. Accepted authoritative configurations remain unchanged.

With `rpc` enabled, the full `easytier-cli` can inspect node, peer, route
and connector status at `127.0.0.1:15888`. Override it with
`--rpc-portal 127.0.0.1:15889` to run another node on the same host.

## Resource Policy

`low-memory` reduces peer ingress, host egress and UDP session queues from
128 to 32 entries. UDP's four reserved control slots and backpressure
remain intact. STUN response retention shrinks from 1,024 to 32 entries.
This trades burst absorption for memory savings: UDP ingress can drop
excess datagrams sooner. Packet sizes and MTU are not reduced. Select
`--no-default-features --features tun,dhcp` to retain larger queues.

Statistics recording is omitted from the default; enabling `rpc` or
`official` restores the counters needed by management views.

The 65,535-port random permutation for hard symmetric NAT is created only
on the first such request, saving 131,070 payload bytes per instance
beforehand. Once initialized it persists to preserve request index
continuity. The same complete shuffle and punching algorithm are retained.

The compact native Noise resolver includes only the 25519/ChaChaPoly/SHA256
algorithms used by the protocol. It does not remove secure-mode handshakes
or AES-GCM data encryption. Full-node and `official` builds retain the
complete Noise resolver algorithm set.

## Limits

Unsupported full-node capabilities are normalized out of runtime state,
as in official mini. ChaCha20 falls back to AES-GCM, not plaintext.
However, missing features needed for a virtual interface or DHCP are
reported as errors; `no_tun` with a virtual IP needs `smoltcp`.
Manual routes need `proxy-cidr-monitor`. Use the original feature set for
the official mini userspace/subnet-proxy path.

TCP hole punching, endpoint discovery (`http`, `https`, `txt`, `srv`),
protobuf reflection and full management services remain excluded.
Unsupported peer/listener URL schemes retain the official no-op behavior.
Local config reads one file, without stdin or `${VAR}` expansion.
OSPF messages retain original wire data for unknown-field forwarding.
The smallest binary cannot provide useful panic backtraces.

## Verification

Run isolated Linux network tests as root:

```sh
ET_MINI_TEST_SKIP_DHCP=1 ./easytier-contrib/easytier-mini/test-network.sh /absolute/path/to/easytier-nano
ET_MINI_TEST_SKIP_DHCP=1 ./easytier-contrib/easytier-mini/test-network.sh /absolute/path/to/easytier-nano /absolute/path/to/upstream-mini
```

The script checks encrypted TCP/UDP TUN traffic, exact TCP/UDP payload
round trips and forced three-node relay. With a `dhcp`-enabled build,
omit `ET_MINI_TEST_SKIP_DHCP=1` to also check distinct DHCP addresses.
It reports RSS/thread samples and removes only its own namespaces.
`ET_MINI_TEST_KEEP_LOGS=1` retains configs and logs.
`ET_MINI_TEST_IPV6=1` adds static IPv6 ping and payload checks.
`ET_MINI_TEST_SKIP_DHCP=1` tests a static-address-only binary without DHCP.

See [SIZE_REPORT.md](SIZE_REPORT.md) for the measured comparison and its scope.
